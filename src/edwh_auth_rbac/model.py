"""
Role-Based Access Control (RBAC) Model with Recursive Memberships

This module implements a comprehensive RBAC system that supports:
- Users, groups, and items as identities
- Recursive group memberships (groups can contain other groups)
- Time-bound permissions with start/end dates
- Wildcard permissions (* for all privileges, all identities, or all targets)
- Password hashing with HMAC-SHA512 and per-entry random salts

Mental Model:
The system is built around three core concepts:
1. Identities: Users (people), Groups (collections), and Items (resources)
2. Memberships: Direct relationships between identities (who belongs to what)
3. Permissions: Granted privileges on targets with time constraints

Key Features:
- Recursive membership resolution through database views
- Efficient permission checking using JOINs with recursive membership views
- Flexible identity lookup by email, ID, UUID, or name
- Secure password storage with constant-time validation

Database Schema:
- identity: Core identity records with object_id, type, and credentials
- membership: Direct membership relationships between identities
- permission: Time-bound privilege grants from identity to target
- recursive_memberships: View showing all indirect memberships
- recursive_members: View showing all indirect members

Edge Cases Handled:
- Circular group memberships are prevented by the recursive view logic
- Non-existent targets in permissions are allowed (flexible resource modeling)
- Time-bound permissions with precise datetime validation
- Wildcard permissions that grant broad access rights
- Case-insensitive email handling
- Automatic cleanup of related records when identities are removed
"""

import copy
import datetime as dt
import hashlib
import hmac
import typing as t
import uuid
from typing import Optional
from uuid import UUID

import dateutil.parser
from pydal import DAL, Field, SQLCustomType
from pydal.objects import SQLALL, Query, Table
from typing_extensions import Required

from .helpers import IS_IN_LIST


class DEFAULT:
    pass


SPECIAL_PERMISSIONS = {"*"}


class HasIdentityKey(t.TypedDict):
    """
    Defines a typed dictionary structure for objects with an identity key.

    This class represents a TypedDict where each object must have an 'object_id'
    key. It can be used to enforce a structure for dictionaries holding
    identifiable entities.
    """

    object_id: str


IdentityKey: t.TypeAlias = str | int | UUID | HasIdentityKey
ObjectTypes = t.Literal["user", "group", "item"]
When: t.TypeAlias = str | dt.datetime | t.Type[DEFAULT]

DEFAULT_STARTS = dt.datetime(2000, 1, 1)
DEFAULT_ENDS = dt.datetime(3000, 1, 1)

T = t.TypeVar("T")


def unstr_datetime(s: When | T) -> dt.datetime | T:
    """json helper... might values arrive as str"""
    return dateutil.parser.parse(s) if isinstance(s, str) else t.cast(T, s)


class Password:
    """
    Password provides three class methods:
        - hmac_hash(value, key, salt=None): compute HMAC-SHA512 of value using key; if salt is provided it's fed into the HMAC update.
        - encode(password): generate a random salt (uuid4.hex) and return ": " where the HMAC uses a hard-coded key "secret_start".
        - validate(password, candidate): split candidate into salt and hash and compare recomputed HMAC to the stored hash.

    - How it's used: encode() is called when creating/updating identities (stored in encoded_password). validate() is used during authentication to check a supplied password.
    - Data format: encoded_password = ": ".
    - Strengths: uses HMAC with SHA‑512 and a per-entry random salt.

    Minimal examples (how to use now)
    - Encoding to store when creating/updating a user:
        - encoded = Password.encode("s3cr3t")
        - store encoded in encoded_password field

    - Validating at login:
        - ok = Password.validate("s3cr3t", stored_encoded_password)
        - returns True/False

    - On encode:
        - generate salt
        - run Argon2/PBKDF2 with parameters -> produce hash
        - return formatted string with metadata

    - On validate:
        - parse metadata
        - compute hash with same parameters
        - compare with constant-time compare
        - if parameters are weaker than current policy, rehash with stronger policy and save on successful login
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


def is_uuid(s: str | UUID) -> bool:
    if isinstance(s, UUID):
        return True

    try:
        UUID(s)
        return True
    except Exception:
        return False


def key_lookup_query(db: DAL, identity_key: IdentityKey, object_type: Optional[ObjectTypes] = None) -> Query:
    """
    Builds a database query to find an identity based on various key formats.

    This function creates a query to look up identities in the database using different
    types of identity keys. It supports lookup by dictionary, email, ID, UUID, or name.

    Parameters
    ----------
    db : DAL
        The database connection object
    identity_key : IdentityKey
        The key to look up. Can be:
        - dict: with 'object_id', 'email', or 'name' keys
        - str: email address (contains '@') or name
        - int: database ID
        - UUID: object UUID
    object_type : Optional[ObjectTypes], optional
        Filter results by object type ('user', 'group', 'item'), by default None

    Returns
    -------
    Query
        A pydal Query object that can be used to select matching records

    Examples
    -------
    >>> query = key_lookup_query(db, "user@example.com", "user")
    >>> query = key_lookup_query(db, uuid.uuid4(), "group")
    """

    if isinstance(identity_key, dict):
        return key_lookup_query(
            db,
            identity_key.get("object_id") or identity_key.get("email") or identity_key.get("name"),
            object_type=object_type,
        )
    elif "@" in str(identity_key):
        query = db.identity.email == str(identity_key).lower()
    elif isinstance(identity_key, int):
        query = db.identity.id == identity_key
    elif is_uuid(identity_key):
        query = db.identity.object_id == str(identity_key).lower()
    else:
        # e.g. for groups, simple lookup by name
        query = db.identity.firstname == identity_key

    if object_type:
        query &= db.identity.object_type == object_type

    return query


def key_lookup(
    db: DAL,
    identity_key: IdentityKey,
    object_type: Optional[ObjectTypes] = None,
    strict: bool = True,
) -> str:
    """
    Looks up an object ID based on the provided identity key in the specified database.
    This function retrieves matching results and ensures correctness based on the strict
    parameter to prevent ambiguity when multiple or no matches are found.

    Args:
        db (DAL): The database object used to perform the lookup query.
        identity_key (IdentityKey): The key used to identify the object in the database.
        object_type (Optional[ObjectTypes]): Specifies the type of object to limit the
            search. Defaults to None, meaning the search is not limited to a specific type.
        strict (bool): Determines whether the function raises an exception when the lookup
            does not return exactly one match (strict=True) or returns None (strict=False).
            Defaults to True.

    Raises:
        ValueError: If strict is True and the number of results is not exactly one.

    Returns:
        str: The object ID corresponding to the identity key if exactly one match is found.
    """
    # if isinstance(identity_key, str) and identity_key in SPECIAL_PERMISSIONS:
    #     return identity_key

    query = key_lookup_query(db, identity_key, object_type)

    rowset = db(query).select(db.identity.object_id)

    if len(rowset) != 1:
        if strict:
            raise ValueError(f"Key lookup for {identity_key} returned {len(rowset)} results.")
        else:
            return None

    return rowset.first().object_id


my_datetime = SQLCustomType(
    type="string",
    native="char(35)",
    encoder=(lambda x: x.isoformat(" ")),
    decoder=(lambda x: dateutil.parser.parse(x)),
)


class RbacKwargs(t.TypedDict, total=False):
    allowed_types: Required[list[str]]
    migrate: bool
    redefine: bool


class Identity(t.Protocol):
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
    """
    Defines the RBAC (Role-Based Access Control) database schema.

    This function creates the necessary database tables for implementing a role-based
    access control system with recursive memberships. It sets up tables for identities,
    group memberships, permissions, and recursive membership views.

    Tables created:
    - identity: Stores user, group, and item identities with their attributes
    - membership: Defines direct membership relationships between identities
    - permission: Grants privileges to identities on target objects with time bounds
    - recursive_memberships: View showing all indirect memberships (read-only)
    - recursive_members: View showing all indirect members (read-only)

    Parameters
    ----------
    db : DAL
        The database connection object
    other_args : RbacKwargs
        Configuration options including:
        - allowed_types: List of valid object types (e.g., ['user', 'group', 'item'])
        - migrate: Whether to create/modify database tables
        - redefine: Whether to redefine existing tables

    Returns
    -------
    None
        Tables are defined directly on the database object
    """

    migrate = other_args.get("migrate", False)
    redefine = other_args.get("redefine", False)

    db.define_table(
        "identity",
        # std uuid from uuid libs are 36 chars long
        Field(
            "object_id",
            "string",
            length=36,
            unique=True,
            notnull=True,
            default=str(uuid.uuid4()),
        ),
        Field("object_type", "string", requires=(IS_IN_LIST(other_args["allowed_types"]))),
        Field("created", "datetime", default=dt.datetime.now),
        # email needn't be unique, groups can share email addresses, and with people too
        Field("email", "string"),
        Field("firstname", "string", comment="also used as short code for groups"),
        Field("lastname", "string"),
        Field("fullname", "string"),
        Field("encoded_password", "string"),
        migrate=migrate,
        redefine=redefine,
    )

    db.define_table(
        "membership",
        # beide zijn eigenlijk: reference:identity.object_id
        Field("subject", "string", length=36, notnull=True),
        Field("member_of", "string", length=36, notnull=True),
        # Field('starts','datetime', default=DEFAULT_STARTS),
        # Field('ends','datetime', default=DEFAULT_ENDS),
        migrate=migrate,
        redefine=redefine,
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
        redefine=redefine,
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
        redefine=redefine,
        primarykey=["root", "object_id"],  # composed, no primary key
        rname="recursive_memberships",
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
        redefine=redefine,
        primarykey=["root", "object_id"],  # composed, no primary key
        rname="recursive_members",
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
    """
    Adds a new identity (user, group, or item) to the RBAC system.

    This function creates a new identity record in the database and optionally adds
    membership relationships to existing groups. The identity can be a user, group,
    or item depending on the object_type parameter.

    Parameters
    ----------
    db : DAL
        The database connection object
    email : str
        Email address for the identity (converted to lowercase)
    member_of : list[IdentityKey]
        List of groups this identity should be a member of
    name : Optional[str], optional
        Name/firstname for the identity (aliases to firstname parameter)
    firstname : Optional[str], optional
        First name for the identity (aliases to name parameter)
    fullname : Optional[str], optional
        Full name for the identity
    password : Optional[str], optional
        Password to encode and store for the identity
    gid : Optional[IdentityKey], optional
        Custom object ID to use instead of generating a UUID
    object_type : Optional[ObjectTypes], optional
        Type of identity ('user', 'group', or 'item')

    Returns
    -------
    str
        The object ID of the newly created identity

    Raises
    ------
    ValueError
        If object_type is not provided or if validation fails

    Edge Cases
    ----------
    - If member_of contains invalid group keys, those memberships are skipped
    - If a group in member_of doesn't exist, it's silently ignored
    - The name and firstname parameters are treated as equivalent
    - Email addresses are automatically converted to lowercase
    - If gid is provided, it's used as the object_id instead of generating a new UUID
    """

    email = email.lower().strip()
    if object_type is None:
        raise ValueError("object_type parameter expected")
    object_id = gid or uuid.uuid4()
    result = db.identity.validate_and_insert(
        object_id=object_id,
        object_type=object_type,
        email=email,
        firstname=name or firstname or None,
        fullname=fullname,
        encoded_password=Password.encode(password) if password else None,
    )

    if e := result.get("errors"):
        raise ValueError(e)

    # db.commit()
    for key in member_of:
        group_id = key_lookup(db, key, "group")
        if get_group(db, group_id):
            # check each group if it exists.
            add_membership(db, identity_key=object_id, group_key=group_id)
    # db.commit()
    return str(object_id)


def add_group(
    db: DAL,
    email: str,
    name: str,
    member_of: list[IdentityKey],
    gid: Optional[str] = None,
):
    """
    Adds a new group identity to the RBAC system.

    This function creates a new group identity record in the database and optionally adds
    membership relationships to existing groups. Groups are a special type of identity
    used to organize users and other groups into logical collections.

    Parameters
    ----------
    db : DAL
        The database connection object
    email : str
        Email address for the group (converted to lowercase)
    name : str
        Name/short code for the group (stored as firstname in the identity table)
    member_of : list[IdentityKey]
        List of parent groups this group should be a member of
    gid : Optional[str], optional
        Custom object ID to use instead of generating a UUID

    Returns
    -------
    str
        The object ID of the newly created group

    Edge Cases
    ----------
    - If member_of contains invalid group keys, those memberships are skipped
    - If a parent group in member_of doesn't exist, it's silently ignored
    - Email addresses are automatically converted to lowercase
    - If gid is provided, it's used as the object_id instead of generating a new UUID
    """

    return add_identity(db, email, member_of, name=name, object_type="group", gid=gid)


def remove_identity(db: DAL, object_id: IdentityKey) -> bool:
    """
    Removes an identity (user, group, or item) from the RBAC system.

    This function deletes an identity record from the database based on its object ID.
    Note that this operation only removes the identity itself and does not automatically
    clean up related membership relationships or permissions.

    Parameters
    ----------
    db : DAL
        The database connection object
    object_id : IdentityKey
        The object ID of the identity to remove

    Returns
    -------
    bool
        True if an identity was found and removed, False otherwise

    Edge Cases
    ----------
    - Related membership records and permissions are not automatically removed
    - Returns False if no identity with the given object_id exists
    - Does not validate if the identity has dependencies
    """

    removed = db(db.identity.object_id == object_id).delete()
    # todo: remove permissions and group memberships
    # db.commit()
    return removed > 0


def get_identity(db: DAL, key: IdentityKey | None, object_type: Optional[ObjectTypes] = None) -> Identity | None:
    """
    :param db: dal db connection
    :param key: can be the email, id, or object_id
    :param object_type: what type of object to look for

    :return: user record or None when not found
    """
    if key is None:
        return None

    query = key_lookup_query(db, key, object_type)
    rows = db(query).select(limitby=(0, 1))
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
    db: DAL,
    password: Optional[str] = None,
    user: Optional[Identity] = None,
    key: Optional[IdentityKey] = None,
) -> bool:
    """
    Authenticates a user by validating their password against the stored hash.

    This function checks if a provided password matches the stored encoded password
    for a given user. The user can be specified either directly or through a lookup key.

    Parameters
    ----------
    db : DAL
        The database connection object
    password : Optional[str], optional
        The password to validate
    user : Optional[Identity], optional
        The user identity object to authenticate
    key : Optional[IdentityKey], optional
        The key to look up the user if user object is not provided

    Returns
    -------
    bool
        True if authentication is successful, False otherwise

    Edge Cases
    ----------
    - Returns False if no password is provided
    - Returns False if user cannot be found via key lookup
    - Uses constant-time comparison to prevent timing attacks
    """

    if not password:
        return False

    if not user and key:
        user = get_user(db, key)

    if user:
        return Password.validate(password, user.encoded_password)

    return False


def add_membership(db: DAL, identity_key: IdentityKey, group_key: IdentityKey) -> None:
    """
    Adds a membership relationship between an identity and a group.

    This function creates a direct membership relationship where an identity
    (user, group, or item) becomes a member of a group. Duplicate memberships
    are automatically prevented.

    Parameters
    ----------
    db : DAL
        The database connection object
    identity_key : IdentityKey
        The identity that will become a member of the group
    group_key : IdentityKey
        The group that the identity will join

    Returns
    -------
    None

    Raises
    ------
    ValueError
        If the identity_key or group_key is invalid/not found

    Edge Cases
    ----------
    - If the membership already exists, it is silently ignored
    - Both identity and group must exist in the database
    - Invalid identity or group keys raise ValueError
    - Uses key_lookup with strict=True, so ambiguous lookups raise exceptions
    """

    identity_oid = key_lookup(db, identity_key)
    if identity_oid is None:
        raise ValueError(f"invalid identity_oid key: {identity_key}")
    group = get_group(db, group_key)
    if not group:
        raise ValueError(f"invalid group key: {group_key}")
    query = db.membership.subject == identity_oid
    query &= db.membership.member_of == group.object_id
    if db(query).count() == 0:
        result = db.membership.validate_and_insert(
            subject=identity_oid,
            member_of=group.object_id,
        )
        if e := result.get("errors"):
            raise ValueError(e)
    # db.commit()


def remove_membership(db: DAL, identity_key: IdentityKey, group_key: IdentityKey) -> int:
    """
    Removes a membership relationship between an identity and a group.

    This function deletes an existing direct membership relationship. It removes
    the specified identity from the specified group.

    Parameters
    ----------
    db : DAL
        The database connection object
    identity_key : IdentityKey
        The identity whose membership should be removed
    group_key : IdentityKey
        The group from which the identity should be removed

    Returns
    -------
    int
        The number of membership records deleted (0 or 1)

    Edge Cases
    ----------
    - Returns 0 if the membership relationship doesn't exist
    - Both identity and group must exist in the database
    - Invalid identity or group keys raise exceptions from get_identity/get_group
    - Only removes direct memberships, not recursive ones
    """

    identity = get_identity(db, identity_key)
    group = get_group(db, group_key)
    query = db.membership.subject == identity.object_id
    query &= db.membership.member_of == group.object_id
    deleted = db(query).delete()
    # db.commit()
    return deleted


def get_memberships(db: DAL, object_id: IdentityKey, bare: bool = True):
    """
    Retrieves all groups that an identity is a member of (including indirect memberships).

    This function queries the recursive_memberships view to find all groups that
    the specified identity belongs to, including both direct and indirect memberships
    through group nesting.

    Parameters
    ----------
    db : DAL
        The database connection object
    object_id : IdentityKey
        The identity whose memberships should be retrieved
    bare : bool, optional
        If True, return only object_id and object_type fields; if False, return all fields

    Returns
    -------
    Row
        A row object containing the membership records

    Edge Cases
    ----------
    - Returns empty result if the identity has no memberships
    - Uses the recursive_memberships view which includes nested group memberships
    """

    query = db.recursive_memberships.root == object_id
    fields = [db.recursive_memberships.object_id, db.recursive_memberships.object_type] if bare else []
    return db(query).select(*fields)


def get_members(db: DAL, object_id: IdentityKey, bare: bool = True):
    """
    Retrieves all identities that are members of a group (including indirect members).

    This function queries the recursive_members view to find all identities that
    belong to the specified group, including both direct and indirect members
    through group nesting.

    Parameters
    ----------
    db : DAL
        The database connection object
    object_id : IdentityKey
        The group whose members should be retrieved
    bare : bool, optional
        If True, return only object_id and object_type fields; if False, return all fields

    Returns
    -------
    Row
        A row object containing the member records

    Edge Cases
    ----------
    - Returns empty result if the group has no members
    - Uses the recursive_members view which includes nested group members
    """

    query = db.recursive_members.root == object_id
    fields = [db.recursive_members.object_id, db.recursive_members.object_type] if bare else []
    return db(query).select(*fields)


def add_permission(
    db: DAL,
    identity_key: IdentityKey | t.Literal["*"],
    target_key: IdentityKey | t.Literal["*"],
    privilege: str,
    starts: dt.datetime | str = DEFAULT_STARTS,
    ends: dt.datetime | str = DEFAULT_ENDS,
) -> None:
    """
    Grants a permission to an identity on a target object with time bounds.

    This function creates a permission record granting a specific privilege to
    an identity (user or group) on a target object, with optional start and end times.

    Parameters
    ----------
    db : DAL
        The database connection object
    identity_key : IdentityKey | t.Literal["*"]
        The identity being granted permission, or "*" for wildcard
    target_key : IdentityKey | t.Literal["*"]
        The target object for the permission, or "*" for wildcard
    privilege : str
        The privilege being granted (e.g., "read", "write")
    starts : dt.datetime | str, optional
        When the permission becomes active (default: DEFAULT_STARTS)
    ends : dt.datetime | str, optional
        When the permission expires (default: DEFAULT_ENDS)

    Returns
    -------
    None

    Edge Cases
    ----------
    - If permission already exists for the same identity, target, and privilege at the start time, it's skipped
    - Identity must exist in the database (except for "*" wildcard)
    - Target doesn't need to exist in the database (can be any UUID)
    - Time bounds are parsed if provided as strings
    - Duplicate permissions are silently ignored
    """

    # identity must exist in the db
    identity_oid = key_lookup(db, identity_key)
    # target can exist as identity, or be any other uuid:
    target_oid = key_lookup(db, target_key, strict=False) or target_key

    starts = unstr_datetime(starts)
    ends = unstr_datetime(ends)
    if has_permission(db, identity_oid, target_oid, privilege, when=starts):
        # permission already granted. just skip it
        print(f"{privilege} permission already granted to {identity_key} on {target_oid} @ {starts} ")
        return

    result = db.permission.validate_and_insert(
        privilege=privilege,
        identity_object_id=identity_oid,
        target_object_id=target_oid,
        starts=starts,
        ends=ends,
    )
    if e := result.get("errors"):
        raise ValueError(e)
    # db.commit()


def remove_permission(
    db: DAL,
    identity_key: IdentityKey,
    target_oid: IdentityKey,
    privilege: str,
    when: When | None = DEFAULT,
) -> bool:
    """
    Revokes a permission from an identity on a target object.

    This function removes an existing permission record based on identity, target,
    privilege, and time constraints. It deletes permissions that are active at
    the specified time.

    Parameters
    ----------
    db : DAL
        The database connection object
    identity_key : IdentityKey
        The identity whose permission should be revoked
    target_oid : IdentityKey
        The target object for which permission is revoked
    privilege : str
        The privilege being revoked
    when : When | None, optional
        The time at which to check for active permissions (default: current time)

    Returns
    -------
    bool
        True if a permission was found and removed, False otherwise

    Edge Cases
    ----------
    - Only removes permissions that are active at the specified time
    - Returns False if no matching permission is found
    - Uses exact matching on identity, target, and privilege
    - Time bounds are considered when determining active permissions
    """

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
    return result


def with_alias(db: DAL, source: Table, alias: str) -> Table:
    """
    Creates an aliased copy of a database table for use in complex queries.

    This function creates a copy of a table with a new alias name, allowing the
    same table to be referenced multiple times in a single query (e.g., for joins).
    This is particularly useful for recursive queries.

    Parameters
    ----------
    db : DAL
        The database connection object
    source : Table
        The source table to be aliased
    alias : str
        The alias name for the new table reference

    Returns
    -------
    Table
        A new table object with the specified alias

    Edge Cases
    ----------
    - The aliased table is added to the database object under the alias name
    - Field references are properly bound to the new aliased table
    - ID fields are handled specially to maintain referential integrity
    - Used internally for recursive membership queries
    """

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
    db: DAL,
    user_or_group_key: IdentityKey,
    target_key: IdentityKey,
    privilege: str,
    when: When | None = DEFAULT,
) -> bool:
    """
    Checks if an identity has a specific permission on a target object at a given time.

    This function determines whether a user or group has been granted a specific privilege
    on a target object, considering both direct permissions and permissions inherited
    through group memberships. It also takes into account time-based permission validity.

    Parameters
    ----------
    db : DAL
        The database connection object
    user_or_group_key : IdentityKey
        The user or group whose permissions are being checked
    target_key : IdentityKey
        The target object for which permission is being checked
    privilege : str
        The privilege to check for (e.g., "read", "write")
    when : When | None, optional
        The time at which to check permissions (default: current time)

    Returns
    -------
    bool
        True if the identity has the specified permission on the target, False otherwise

    Edge Cases
    ----------
    - Uses recursive membership views to check permissions inherited through group nesting
    - Supports wildcard permissions (privilege "*") that grant all privileges
    - Time bounds are checked to ensure permissions are active at the specified time
    - If when is DEFAULT, current time is used for the check
    - Invalid user_or_group_key raises exception from key_lookup
    - Non-existent target_key is handled gracefully and used as-is
    """
    root_oid = key_lookup(db, user_or_group_key)
    target_oid = key_lookup(db, target_key, strict=False) or target_key

    # the permission system
    if when is DEFAULT:
        when = dt.datetime.now()
    else:
        when = unstr_datetime(when)
    # base object is is the root to check for, user or group
    permission = db.permission
    # ugly hack to satisfy pydal aliasing keyed tables /views
    left = with_alias(db, db.recursive_memberships, "left")
    right = with_alias(db, db.recursive_memberships, "right")
    # left = db.recursive_memberships.with_alias('left')
    # right = db.recursive_memberships.with_alias('right')

    # end of ugly hack
    query = left.root == root_oid  # | (left.root == "*")
    query &= right.root == target_oid  # | (right.root == "*")
    query &= permission.identity_object_id == left.object_id  # | (permission.identity_object_id == "*")
    query &= permission.target_object_id == right.object_id  # | (permission.target_object_id == "*")
    query &= (permission.privilege == privilege) | (permission.privilege == "*")
    query &= permission.starts <= when
    query &= permission.ends >= when

    return db(query).count() > 0


def get_permissions(
    db: DAL,
    user_or_group_key: IdentityKey,
    privilege: str | None = None,
    when: When | None = DEFAULT,
) -> list[IdentityKey]:
    """
    Get all target objects that an identity has permissions on.

    Parameters
    ----------
    db : DAL
        The database connection object
    user_or_group_key : IdentityKey
        The user or group whose permissions are being retrieved
    privilege : str | None, optional
        Specific privilege to filter by. If None, returns all targets
        with any permission
    when : When | None, optional
        The time at which to check permissions (default: current time)

    Returns
    -------
    list[IdentityKey]
        List of target object IDs the identity has permissions on
    """
    root_oid = key_lookup(db, user_or_group_key)

    if when is DEFAULT:
        when = dt.datetime.now()
    else:
        when = unstr_datetime(when)

    permission = db.permission
    left = with_alias(db, db.recursive_memberships, "left")
    right = with_alias(db, db.recursive_memberships, "right")

    query = left.root == root_oid
    query &= right.root == db.identity.object_id
    query &= permission.identity_object_id == left.object_id
    query &= permission.target_object_id == right.object_id

    if privilege:
        query &= (permission.privilege == privilege) | (permission.privilege == "*")

    query &= permission.starts <= when
    query &= permission.ends >= when

    rows = db(query).select(right.object_id, distinct=True)
    return [row.object_id for row in rows]


def get_permissions_subquery(
    db: DAL,
    user_or_group_key: IdentityKey,
    privilege: str | None = None,
    when: When | None = DEFAULT,
):
    """
    Get a subquery for all target objects that an identity has
    permissions on.

    Useful for composing larger queries that need to filter by
    permissions.

    Parameters
    ----------
    db : DAL
        The database connection object
    user_or_group_key : IdentityKey
        The user or group whose permissions are being retrieved
    privilege : str | None, optional
        Specific privilege to filter by. If None, returns all targets
        with any permission
    when : When | None, optional
        The time at which to check permissions (default: current time)

    Returns
    -------
    Query
        A subquery that can be used in other database queries
    """
    root_oid = key_lookup(db, user_or_group_key)

    if when is DEFAULT:
        when = dt.datetime.now()
    else:
        when = unstr_datetime(when)

    permission = db.permission
    left = with_alias(db, db.recursive_memberships, "left")
    right = with_alias(db, db.recursive_memberships, "right")

    query = left.root == root_oid
    query &= right.root == db.identity.object_id
    query &= permission.identity_object_id == left.object_id
    query &= permission.target_object_id == right.object_id

    if privilege:
        query &= (permission.privilege == privilege) | (permission.privilege == "*")

    query &= permission.starts <= when
    query &= permission.ends >= when

    return db(query)._select(right.object_id)
