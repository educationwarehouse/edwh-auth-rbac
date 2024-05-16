import copy
import datetime
import hashlib
import hmac
import uuid

import dateutil.parser
from pydal import Field
from pydal import SQLCustomType
from pydal.objects import SQLALL, Query

from .helpers import IS_IN_LIST


class DEFAULT:
    pass


DEFAULT_STARTS = datetime.datetime(2000, 1, 1)
DEFAULT_ENDS = datetime.datetime(3000, 1, 1)


def unstr_datetime(s):
    """json helper... might values arrive as str """
    return dateutil.parser.parse(s) if isinstance(s, str) else s


class Password:
    """
    Encode a password using: Password.encode('secret')
    """

    @classmethod
    def hmac_hash(cls, value, key, salt=None):
        digest_alg = hashlib.sha512
        d = hmac.new(str(key).encode(), str(value).encode(), digest_alg)
        if salt:
            d.update(str(salt).encode())
        return d.hexdigest()

    @classmethod
    def validate(cls, password, candidate):
        salt, hashed = candidate.split(':', 1)
        return cls.hmac_hash(value=password, key='secret_start', salt=salt) == hashed

    @classmethod
    def encode(cls, password):
        salt = uuid.uuid4().hex
        return salt + ':' + cls.hmac_hash(value=password, key='secret_start', salt=salt)


def is_uuid(s):
    try:
        uuid.UUID(s)
        return True
    except Exception:
        return False


def key_lookup_query(db, identity_key: str | int | uuid.UUID, object_type=None) -> Query:
    if '@' in str(identity_key):
        query = db.identity.email == identity_key.lower()
    elif isinstance(identity_key, int):
        query = db.identity.id == identity_key
    elif is_uuid(identity_key):
        query = db.identity.object_id == identity_key.lower()
    else:
        query = db.identity.firstname == identity_key

    if object_type:
        query &= db.identity.object_type == object_type

    return query


def key_lookup(db, identity_key, object_type=None) -> str | None:
    query = key_lookup_query(db, identity_key, object_type)

    rowset = db(query).select(db.identity.object_id)

    if not rowset:
        return None
    elif len(rowset) > 1:
        raise ValueError('Keep lookup for {} returned {} results.'.format(identity_key, len(rowset)))

    return rowset.first().object_id


my_datetime = SQLCustomType(type='string',
                            native='char(35)',
                            encoder=(lambda x: x.isoformat(' ')),
                            decoder=(lambda x: dateutil.parser.parse(x)))


def define_auth_rbac_model(db, other_args):
    db.define_table('identity',
                    # std uuid from uuid libs are 36 chars long
                    Field('object_id', 'string', length=36, unique=True, notnull=True, default=str(uuid.uuid4())),
                    Field('object_type', 'string', requires=(IS_IN_LIST(other_args['allowed_types']))),
                    Field('created', 'datetime', default=datetime.datetime.now),
                    # email needn't be unique, groups can share email addresses, and with people too
                    Field('email', 'string'),
                    Field('firstname', 'string', comment='also used as short code for groups'),
                    Field('fullname', 'string'),
                    Field('encoded_password', 'string'),
                    )

    db.define_table('membership',
                    # beide zijn eigenlijk: reference:identity.object_id
                    Field('subject', 'string', length=36, notnull=True),
                    Field('member_of', 'string', length=36, notnull=True),
                    # Field('starts','datetime', default=DEFAULT_STARTS),
                    # Field('ends','datetime', default=DEFAULT_ENDS),
                    )

    db.define_table('permission',
                    Field('privilege', 'string', length=20),
                    # reference:identity.object_id
                    Field('identity_object_id', 'string', length=36),
                    Field('target_object_id', 'string', length=36),
                    # Field('scope'), lets bail scope for now. every one needs a rule for everything
                    # just to make sure, no 'wildcards' and 'every dossier for org x' etc ...
                    Field('starts', type=my_datetime, default=DEFAULT_STARTS),
                    Field('ends', type=my_datetime, default=DEFAULT_ENDS),
                    )

    db.define_table('recursive_memberships',
                    Field('root'),
                    Field('object_id'),
                    Field('object_type'),
                    Field('level', 'integer'),
                    Field('email'),
                    Field('firstname'),
                    Field('fullname'),
                    migrate=False,
                    primarykey=['root', 'object_id']  # composed, no primary key
                    )
    db.define_table('recursive_members',
                    Field('root'),
                    Field('object_id'),
                    Field('object_type'),
                    Field('level', 'integer'),
                    Field('email'),
                    Field('firstname'),
                    Field('fullname'),
                    migrate=False,
                    primarykey=['root', 'object_id']  # composed, no primary key
                    )


def add_identity(db, email, password, member_of, name=None, firstname=None, fullname=None, gid=None, object_type=None):
    """paramaters name and firstname are equal. """
    email = email.lower().strip()
    if object_type is None:
        raise ValueError('object_type parameter expected')
    object_id = gid if gid else str(uuid.uuid4())
    db.identity.validate_and_insert(
        object_id=object_id,
        object_type=object_type,
        email=email,
        firstname=name or firstname or None,
        fullname=fullname,
        encoded_password=Password.encode(password)
    )
    db.commit()
    for key in member_of:
        group_id = key_lookup(db, key, 'group')
        if get_group(db, group_id):
            # check each group if it exists.
            add_membership(db, identity_key=object_id, group_key=group_id)
    db.commit()
    return object_id


def add_group(db, email, name, member_of):
    return add_identity(db, email, None, member_of, name=name, object_type='group')


def remove_identity(db, object_id):
    removed = db(db.identity.object_id == object_id).delete()
    # todo: remove permissions and group memberships
    db.commit()
    return removed > 0


def get_identity(db, key, object_type=None):
    """
    :param db: dal db connection
    :param key: can be the email, id, or object_id
    :return: user record or None when not found
    """
    query = key_lookup_query(db, key, object_type)
    rows = db(query).select()
    return rows.first()


def get_user(db, key):
    """
    :param db: dal db connection
    :param key: can be the email, id, or object_id
    :return: user record or None when not found
    """
    return get_identity(db, key, object_type='user')


def get_group(db, key):
    """

    :param db: dal db connection
    :param key: can be the name of the group, the id, object_id or email_address
    :return: user record or None when not found
    """
    return get_identity(db, key, object_type='group')


def authenticate_user(db, password=None, user=None, key=None):
    if not password:
        return False
    if not user:
        user = get_user(db, key)
    return Password.validate(password, user.encoded_password)


def add_membership(db, identity_key, group_key):
    identity_oid = key_lookup(db, identity_key)
    if identity_oid is None:
        raise ValueError('invalid identity_oid key: ' + identity_key)
    group = get_group(db, group_key)
    if not group:
        raise ValueError('invalid group key: ' + group_key)
    query = db.membership.subject == identity_oid
    query &= db.membership.member_of == group.object_id
    if db(query).count() == 0:
        db.membership.validate_and_insert(
            subject=identity_oid,
            member_of=group.object_id,
        )
    db.commit()


def remove_membership(db, identity_key, group_key):
    identity = get_identity(db, identity_key)
    group = get_group(db, group_key)
    query = db.membership.subject == identity.object_id
    query &= db.membership.member_of == group.object_id
    deleted = db(query).delete()
    db.commit()
    return deleted


def get_memberships(db, object_id, bare=True):
    query = db.recursive_memberships.root == object_id
    fields = [db.recursive_memberships.object_id, db.recursive_memberships.object_type]
    if not bare:
        fields = []
    return db(query).select(*fields)


def get_members(db, object_id, bare=True):
    query = db.recursive_members.root == object_id
    fields = [db.recursive_members.object_id, db.recursive_members.object_type]
    if not bare:
        fields = []
    return db(query).select(*fields)


def add_permission(db, identity_key, target_oid, privilege, starts=DEFAULT_STARTS, ends=DEFAULT_ENDS):
    identity_oid = key_lookup(db, identity_key)
    starts = unstr_datetime(starts)
    ends = unstr_datetime(ends)
    if has_permission(db, identity_oid, target_oid, privilege, when=starts):
        # permission already granted. just skip it
        print(
            '{privilege} permission already granted to {user_or_group_key} on {target_oid} @ {starts} '.format(
                **locals()))
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


def remove_permission(db, identity_key, target_oid, privilege, when=DEFAULT):
    identity_oid = key_lookup(db, identity_key)
    if when is DEFAULT:
        when = datetime.datetime.now()
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


def with_alias(db, source, alias):
    other = copy.copy(source)
    other['ALL'] = SQLALL(other)
    other['_tablename'] = alias
    for fieldname in other.fields:
        tmp = source[fieldname].clone()
        tmp.bind(other)
        other[fieldname] = tmp
    if 'id' in source and 'id' not in other.fields:
        other['id'] = other[source.id.name]

    if source_id := getattr(source, "_id", None):
        other._id = other[source_id.name]
    db[alias] = other
    return other


def has_permission(db, user_or_group_key, target_oid, privilege, when=DEFAULT):
    user_or_group_oid = key_lookup(db, user_or_group_key)
    # the permission system
    if when is DEFAULT:
        when = datetime.datetime.now()
    else:
        when = unstr_datetime(when)
    # base object is is the root to check for, user or group
    root_oid = user_or_group_oid
    permission = db.permission
    # ugly hack to satisfy pydal aliasing keyed tables /views
    left = with_alias(db, db.recursive_memberships, 'left')
    right = with_alias(db, db.recursive_memberships, 'right')
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
