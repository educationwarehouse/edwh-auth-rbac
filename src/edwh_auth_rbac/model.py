import copy
import datetime as dt
import hashlib
import hmac
import typing
import uuid
from typing import Optional
from uuid import UUID

import dateutil.parser
from pydal import DAL, Field, SQLCustomType
from pydal.objects import SQLALL, Query, Table

from .helpers import IS_IN_LIST


class DEFAULT:
    pass


IdentityKey: typing.TypeAlias = str | int | UUID
ObjectTypes = typing.Literal["user", "group", "item"]
When: typing.TypeAlias = str | dt.datetime | typing.Type[DEFAULT]

DEFAULT_STARTS = dt.datetime(2000, 1, 1)
DEFAULT_ENDS = dt.datetime(3000, 1, 1)

T = typing.TypeVar("T")


def unstr_datetime(s: When | T) -> dt.datetime | T:
    """json helper... might values arrive as str"""
    return dateutil.parser.parse(s) if isinstance(s, str) else typing.cast(T, s)


class Password:
    """
    Encode a password using: Password.encode('secret')
    """

    @classmethod
    def hmac_hash(cls, value: str, key: str, salt: Optional[str] = None) -> str:
        digest_alg = hashlib.sha512
        d = hmac.new(str(key).encode(), str(value).encode(), digest_alg)
        if salt:
            d.update(str(salt).encode())
        return d.hexdigest()

    @classmethod
    def validate(cls, password: str, candidate: str) -> bool:
        salt, hashed = candidate.split(":", 1)
        return cls.hmac_hash(value=password, key="secret_start", salt=salt) == hashed

    @classmethod
    def encode(cls, password: str) -> str:
        salt = uuid.uuid4().hex
        return salt + ":" + cls.hmac_hash(value=password, key="secret_start", salt=salt)


def is_uuid(s) -> bool:
    try:
        UUID(s)
        return True
    except Exception:
        return False


def key_lookup_query(db: DAL, identity_key: IdentityKey, object_type: Optional[ObjectTypes] = None) -> Query:
    if "@" in str(identity_key):
        query = db.identity.email == str(identity_key).lower()
    elif isinstance(identity_key, int):
        query = db.identity.id == identity_key
    elif is_uuid(identity_key):
        query = db.identity.object_id == str(identity_key).lower()
    else:
        query = db.identity.firstname == identity_key

    if object_type:
        query &= db.identity.object_type == object_type

    return query


def key_lookup(db: DAL, identity_key: IdentityKey, object_type: Optional[ObjectTypes] = None) -> str:
    query = key_lookup_query(db, identity_key, object_type)

    rowset = db(query).select(db.identity.object_id)

    if len(rowset) != 1:
        raise ValueError("Keep lookup for {} returned {} results.".format(identity_key, len(rowset)))

    return rowset.first().object_id


my_datetime = SQLCustomType(
    type="string", native="char(35)", encoder=(lambda x: x.isoformat(" ")), decoder=(lambda x: dateutil.parser.parse(x))
)


class RbacKwargs(typing.TypedDict, total=False):
    allowed_types: list[str]
    migrate: bool


class Identity(typing.Protocol):
    object_id: str
    object_type: str
    created: dt.datetime
    email: str
    firstname: str
    lastname: Optional[str]
    fullname: str
    encoded_password: str

    def update_record(self, **data) -> None: ...


def define_auth_rbac_model(db: DAL, other_args: RbacKwargs):
    migrate = other_args.get("migrate", False)

    db.define_table(
        "identity",
        # std uuid from uuid libs are 36 chars long
        Field("object_id", "string", length=36, unique=True, notnull=True, default=str(uuid.uuid4())),
        Field("object_type", "string", requires=(IS_IN_LIST(other_args["allowed_types"]))),
        Field("created", "datetime", default=dt.datetime.now),
        # email needn't be unique, groups can share email addresses, and with people too
        Field("email", "string"),
        Field("firstname", "string", comment="also used as short code for groups"),
        Field("lastname", "string"),
        Field("fullname", "string"),
        Field("encoded_password", "string"),
        migrate=migrate,
    )

    db.define_table(
        "membership",
        # beide zijn eigenlijk: reference:identity.object_id
        Field("subject", "string", length=36, notnull=True),
        Field("member_of", "string", length=36, notnull=True),
        # Field('starts','datetime', default=DEFAULT_STARTS),
        # Field('ends','datetime', default=DEFAULT_ENDS),
        migrate=migrate,
    )

    db.define_table(
        "permission",
        Field("privilege", "string", length=20),
        # reference:identity.object_id
        Field("identity_object_id", "string", length=36),
        Field("target_object_id", "string", length=36),
        # Field('scope'), lets bail scope for now. every one needs a rule for everything
        # just to make sure, no 'wildcards' and 'every dossier for org x' etc ...
        Field("starts", type=my_datetime, default=DEFAULT_STARTS),
        Field("ends", type=my_datetime, default=DEFAULT_ENDS),
        migrate=migrate,
    )

    db.define_table(
        "recursive_memberships",
        Field("root"),
        Field("object_id"),
        Field("object_type"),
        Field("level", "integer"),
        Field("email"),
        Field("firstname"),
        Field("fullname"),
        migrate=False,  # view
        primarykey=["root", "object_id"],  # composed, no primary key
    )
    db.define_table(
        "recursive_members",
        Field("root"),
        Field("object_id"),
        Field("object_type"),
        Field("level", "integer"),
        Field("email"),
        Field("firstname"),
        Field("fullname"),
        migrate=False,  # view
        primarykey=["root", "object_id"],  # composed, no primary key
    )


def add_identity(
    db: DAL,
    email: str,
    member_of: list[IdentityKey],
    name: Optional[str] = None,
    firstname: Optional[str] = None,
    fullname: Optional[str] = None,
    password: Optional[str] = None,
    gid: Optional[IdentityKey] = None,
    object_type: Optional[ObjectTypes] = None,
) -> str:
    """paramaters name and firstname are equal."""
    email = email.lower().strip()
    if object_type is None:
        raise ValueError("object_type parameter expected")
    object_id = gid if gid else uuid.uuid4()
    db.identity.validate_and_insert(
        object_id=object_id,
        object_type=object_type,
        email=email,
        firstname=name or firstname or None,
        fullname=fullname,
        encoded_password=Password.encode(password) if password else None,
    )
    db.commit()
    for key in member_of:
        group_id = key_lookup(db, key, "group")
        if get_group(db, group_id):
            # check each group if it exists.
            add_membership(db, identity_key=object_id, group_key=group_id)
    db.commit()
    return str(object_id)


def add_group(db: DAL, email: str, name: str, member_of: list[IdentityKey]):
    return add_identity(db, email, member_of, name=name, object_type="group")


def remove_identity(db: DAL, object_id: IdentityKey):
    removed = db(db.identity.object_id == object_id).delete()
    # todo: remove permissions and group memberships
    db.commit()
    return removed > 0


def get_identity(db: DAL, key: IdentityKey, object_type: Optional[ObjectTypes] = None) -> Identity:
    """
    :param db: dal db connection
    :param key: can be the email, id, or object_id
    :return: user record or None when not found
    """
    query = key_lookup_query(db, key, object_type)
    rows = db(query).select()
    return rows.first()


def get_user(db: DAL, key: IdentityKey):
    """
    :param db: dal db connection
    :param key: can be the email, id, or object_id
    :return: user record or None when not found
    """
    return get_identity(db, key, object_type="user")


def get_group(db: DAL, key: IdentityKey):
    """

    :param db: dal db connection
    :param key: can be the name of the group, the id, object_id or email_address
    :return: user record or None when not found
    """
    return get_identity(db, key, object_type="group")


def authenticate_user(
    db: DAL, password: Optional[str] = None, user: Optional[Identity] = None, key: Optional[IdentityKey] = None
) -> bool:
    if not password:
        return False

    if not user and key:
        user = get_user(db, key)

    if user:
        return Password.validate(password, user.encoded_password)

    return False


def add_membership(db: DAL, identity_key: IdentityKey, group_key: IdentityKey) -> None:
    identity_oid = key_lookup(db, identity_key)
    if identity_oid is None:
        raise ValueError(f"invalid identity_oid key: {identity_key}")
    group = get_group(db, group_key)
    if not group:
        raise ValueError(f"invalid group key: {group_key}")
    query = db.membership.subject == identity_oid
    query &= db.membership.member_of == group.object_id
    if db(query).count() == 0:
        db.membership.validate_and_insert(
            subject=identity_oid,
            member_of=group.object_id,
        )
    db.commit()


def remove_membership(db: DAL, identity_key: IdentityKey, group_key: IdentityKey) -> int:
    identity = get_identity(db, identity_key)
    group = get_group(db, group_key)
    query = db.membership.subject == identity.object_id
    query &= db.membership.member_of == group.object_id
    deleted = db(query).delete()
    db.commit()
    return deleted


def get_memberships(db: DAL, object_id: IdentityKey, bare: bool = True):
    query = db.recursive_memberships.root == object_id
    fields = [db.recursive_memberships.object_id, db.recursive_memberships.object_type] if bare else []
    return db(query).select(*fields)


def get_members(db: DAL, object_id: IdentityKey, bare: bool = True):
    query = db.recursive_members.root == object_id
    fields = [db.recursive_members.object_id, db.recursive_members.object_type] if bare else []
    return db(query).select(*fields)


def add_permission(
    db: DAL,
    identity_key: IdentityKey,
    target_oid: IdentityKey,
    privilege: str,
    starts: dt.datetime | str = DEFAULT_STARTS,
    ends: dt.datetime | str = DEFAULT_ENDS,
) -> None:
    identity_oid = key_lookup(db, identity_key)
    starts = unstr_datetime(starts)
    ends = unstr_datetime(ends)
    if has_permission(db, identity_oid, target_oid, privilege, when=starts):
        # permission already granted. just skip it
        print(
            "{privilege} permission already granted to {user_or_group_key} on {target_oid} @ {starts} ".format(
                **locals()
            )
        )
        # print(db._lastsql)
        return
    db.permission.validate_and_insert(
        privilege=privilege,
        identity_object_id=identity_oid,
        target_object_id=target_oid,
        starts=starts,
        ends=ends,
    )
    db.commit()


def remove_permission(
    db: DAL, identity_key: IdentityKey, target_oid: IdentityKey, privilege: str, when: When | None = DEFAULT
) -> bool:
    identity_oid = key_lookup(db, identity_key)
    if when is DEFAULT:
        when = dt.datetime.now()
    else:
        when = unstr_datetime(when)
    # base object is is the root to check for, user or group
    permission = db.permission
    query = permission.identity_object_id == identity_oid
    query &= permission.target_object_id == target_oid
    query &= permission.privilege == privilege
    query &= permission.starts <= when
    query &= permission.ends >= when
    result = db(query).delete() > 0
    db.commit()
    # print(db._lastsql)
    return result


def with_alias(db: DAL, source: Table, alias: str) -> Table:
    other = copy.copy(source)
    other["ALL"] = SQLALL(other)
    other["_tablename"] = alias
    for fieldname in other.fields:
        tmp = source[fieldname].clone()
        tmp.bind(other)
        other[fieldname] = tmp
    if "id" in source and "id" not in other.fields:
        other["id"] = other[source.id.name]

    if source_id := getattr(source, "_id", None):
        other._id = other[source_id.name]
    db[alias] = other
    return other


def has_permission(
    db: DAL, user_or_group_key: IdentityKey, target_oid: IdentityKey, privilege: str, when: When | None = DEFAULT
) -> bool:
    user_or_group_oid = key_lookup(db, user_or_group_key)
    # the permission system
    if when is DEFAULT:
        when = dt.datetime.now()
    else:
        when = unstr_datetime(when)
    # base object is is the root to check for, user or group
    root_oid = user_or_group_oid
    permission = db.permission
    # ugly hack to satisfy pydal aliasing keyed tables /views
    left = with_alias(db, db.recursive_memberships, "left")
    right = with_alias(db, db.recursive_memberships, "right")
    # left = db.recursive_memberships.with_alias('left')
    # right = db.recursive_memberships.with_alias('right')

    # end of ugly hack
    query = left.root == root_oid
    query &= right.root == target_oid
    query &= permission.identity_object_id == left.object_id
    query &= permission.target_object_id == right.object_id
    query &= permission.privilege == privilege
    query &= permission.starts <= when
    query &= permission.ends >= when
    return db(query).count() > 0
