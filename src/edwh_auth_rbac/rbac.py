"""
Role-Based Access Control (RBAC) Implementation
This module provides a comprehensive RBAC system that supports:
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

The AuthRbac class serves as the main interface for managing identities,
memberships, and permissions in the RBAC system.

Edge Cases Handled:
- Circular group memberships are prevented by the recursive view logic
- Non-existent targets in permissions are allowed (flexible resource modeling)
- Time-bound permissions with precise datetime validation
- Wildcard permissions that grant broad access rights
- Case-insensitive email handling
- Automatic cleanup of related records when identities are removed
"""
import logging
import typing
from typing import Optional

from pydal import DAL
from typing_extensions import NotRequired, Unpack

from . import model
from .model import (
    DEFAULT,
    DEFAULT_ENDS,
    DEFAULT_STARTS,
    IdentityKey,
    ObjectTypes,
    Password,
    RbacKwargs,
    When,
    define_auth_rbac_model,
    key_lookup,
    unstr_datetime,
)

_pylog = logging.getLogger(__name__)
_pylog.setLevel(logging.INFO)


class MinimalIdentityDict(typing.TypedDict):
    object_id: str
    object_type: NotRequired[ObjectTypes]
    email: str
    name: str


class UserDict(typing.TypedDict):
    """
    Typed dictionary representing a user identity.

    Contains user information including object_id, email, name fields,
    and optional memberships list.
    """

    object_id: str
    email: str
    firstname: str
    fullname: str
    object_type: NotRequired[ObjectTypes]
    memberships: NotRequired[list["UserDict"]]


class GroupDict(typing.TypedDict):
    """
    Typed dictionary representing a group identity.

    Contains group information including object_id, email, name,
    and optional members list.

    Edge Cases:
    - Members list may be empty if group has no members
    """

    object_id: str
    email: str
    name: str
    members: NotRequired[list[MinimalIdentityDict]]


class AuthRbac:
    """
    Main Role-Based Access Control (RBAC) class.

    Provides methods for managing identities (users, groups, items),
    memberships, and permissions in the RBAC system.

    The class uses a pydal database connection to store and retrieve
    RBAC data, and relies on recursive database views for efficient
    membership and permission resolution.

    Attributes:
        db (DAL): The pydal database connection
        name (str): Class name identifier

    Edge Cases:
    - All email addresses are converted to lowercase for consistent lookup
    - Database operations may raise exceptions for constraint violations
    - Recursive group memberships are handled automatically
    """

    name = "auth_rbac"

    def __init__(self, db: DAL):
        """
        Initialize the AuthRbac instance.

        Args:
            db (DAL): The pydal database connection to use
        """
        self.db = db

    def define_model(self, **options: Unpack[RbacKwargs]):
        """
        Define the RBAC database model tables and views.

        Creates the necessary database tables for the RBAC system including:
        identity, membership, permission, and recursive membership views.

        Args:
            **options: Configuration options for model definition
                      including allowed_types, migrate, and redefine flags

        Edge Cases:
        - If migrate=True, tables will be created/modified in the database
        - If redefine=True, existing tables will be redefined
        - allowed_types must be provided to specify valid object types
        """
        define_auth_rbac_model(self.db, options)

    @staticmethod
    def _error(msg):
        """
        Print an error message to stdout.

        Args:
            msg (str): The error message to print
        """
        print("ERROR:", msg)

    # gebruik event en rpc live templates (mobiel)

    def add_user(
        self,
        email: str,
        firstname: str,
        fullname: str,
        password: str,
        member_of: list[IdentityKey],
        gid: Optional[str] = None,
        allow_existing: bool = False,
    ) -> UserDict:
        """
        Add a new user identity to the RBAC system.

        Creates a new user record in the database and optionally adds
        membership relationships to existing groups.

        Args:
            email (str): Email address for the user (converted to lowercase)
            firstname (str): First name for the user
            fullname (str): Full name for the user
            password (str): Password to encode and store for the user
            member_of (list[IdentityKey]): List of groups this user should be a member of
            gid (Optional[str]): Custom object ID to use instead of generating a UUID
            allow_existing (bool): Whether to allow existing users (default: False)

        Returns:
            UserDict: Dictionary containing the created user's information

        Raises:
            ValueError: if the user (by gid or email) already exists and allow_existing is False

        Edge Cases:
        - If member_of contains invalid group keys, those memberships are skipped
        - Email addresses are automatically converted to lowercase
        - If gid is provided, it's used as the object_id instead of generating a new UUID
        - Password is securely hashed before storage
        """
        """
        Raises:
            ValueError: if the user (by gid or email) already exists
        """
        # check if exists
        email = email.lower().strip()
        if rec := model.get_user(self.db, gid or email):
            if not allow_existing:
                raise ValueError("User already exists")
        else:
            object_id = model.add_identity(
                self.db,
                email,
                member_of,
                password=password,
                firstname=firstname,
                fullname=fullname,
                object_type="user",
                gid=gid,
            )
            rec = model.get_user(self.db, object_id)
        return dict(
            object_id=rec.object_id,
            email=rec.email,
            firstname=rec.firstname,
            fullname=rec.fullname,
        )

    def add_item(
        self,
        email: str,
        name: str,
        member_of: list[IdentityKey],
        password: Optional[str] = None,
        gid: Optional[str] = None,
        allow_existing: bool = False,
    ) -> MinimalIdentityDict:
        """
        Add a new item identity to the RBAC system.

        Creates a new item record in the database and optionally adds
        membership relationships to existing groups.

        Args:
            email (str): Email address for the item (converted to lowercase)
            name (str): Name for the item
            member_of (list[IdentityKey]): List of groups this item should be a member of
            password (Optional[str]): Password to encode and store for the item (if applicable)
            gid (Optional[str]): Custom object ID to use instead of generating a UUID
            allow_existing (bool): Whether to allow existing items (default: False)

        Returns:
            MinimalIdentityDict: Dictionary containing the created item's information

        Raises:
            ValueError: if the item (by gid or email) already exists and allow_existing is False

        Edge Cases:
        - If member_of contains invalid group keys, those memberships are skipped
        - Email addresses are automatically converted to lowercase
        - If gid is provided, it's used as the object_id instead of generating a new UUID
        - Password is securely hashed before storage (if provided)
        """

        # check if exists
        email = email.lower().strip()
        if rec := (
            model.get_identity(self.db, email, "item")
            or model.get_identity(self.db, gid, "item")
        ):
            if not allow_existing:
                raise ValueError("Item already exists")
        else:
            object_id = model.add_identity(
                self.db,
                email,
                member_of,
                gid=gid,
                name=name,
                password=password,
                object_type="item",
            )
            rec = model.get_identity(self.db, object_id, object_type="item")

        return dict(object_id=rec.object_id, email=rec.email, name=rec.firstname)

    def add_identity(
        self,
        email: str,
        name: str,
        member_of: list[IdentityKey],
        object_type: ObjectTypes,
        password: Optional[str] = None,
        gid: Optional[str] = None,
        allow_existing: bool = False,
    ) -> MinimalIdentityDict:
        """
        Add a new identity (user, group, or item) to the RBAC system.

        Creates a new identity record in the database and optionally adds
        membership relationships to existing groups.

        Args:
            email (str): Email address for the identity (converted to lowercase)
            name (str): Name for the identity
            member_of (list[IdentityKey]): List of groups this identity should be a member of
            object_type (ObjectTypes): Type of identity ('user', 'group', or 'item')
            password (Optional[str]): Password to encode and store (if applicable)
            gid (Optional[str]): Custom object ID to use instead of generating a UUID
            allow_existing (bool): Whether to allow existing identities (default: False)

        Returns:
            MinimalIdentityDict: Dictionary containing the created identity's information

        Raises:
            ValueError: if the identity already exists and allow_existing is False

        Edge Cases:
        - If member_of contains invalid group keys, those memberships are skipped
        - Email addresses are automatically converted to lowercase
        - If gid is provided, it's used as the object_id instead of generating a new UUID
        - Password is securely hashed before storage (if provided)
        """

        # check if exists
        email = email.lower().strip()

        if rec := model.get_identity(self.db, email, object_type):
            if not allow_existing:
                raise ValueError("Item already exists")
        else:
            object_id = model.add_identity(
                self.db,
                email,
                member_of,
                name,
                password=password,
                object_type=object_type,
                gid=gid,
            )
            rec = model.get_identity(self.db, object_id, object_type=object_type)
        return dict(object_id=rec.object_id, email=rec.email, name=rec.fullname)

    def add_group(
        self,
        email: str,
        name: str,
        member_of: list[IdentityKey],
        gid: Optional[str] = None,
        allow_existing: bool = False,
    ) -> MinimalIdentityDict:
        """
        Add a new group identity to the RBAC system.

        Creates a new group record in the database and optionally adds
        membership relationships to existing groups.

        Args:
            email (str): Email address for the group (converted to lowercase)
            name (str): Name/short code for the group
            member_of (list[IdentityKey]): List of parent groups this group should be a member of
            gid (Optional[str]): Custom object ID to use instead of generating a UUID
            allow_existing (bool): Whether to allow existing groups (default: False)

        Returns:
            MinimalIdentityDict: Dictionary containing the created group's information

        Raises:
            ValueError: if the group already exists and allow_existing is False

        Edge Cases:
        - If member_of contains invalid group keys, those memberships are skipped
        - Email addresses are automatically converted to lowercase
        - If gid is provided, it's used as the object_id instead of generating a new UUID
        """

        # check if exists
        email = email.lower().strip()
        if rec := model.get_group(self.db, gid or email):
            if not allow_existing:
                raise ValueError("Group already exists")
        else:
            object_id = model.add_group(self.db, email, name, member_of, gid=gid)
            rec = model.get_group(self.db, object_id)
        return dict(object_id=rec.object_id, email=rec.email, name=rec.firstname)

    def update_identity(
        self,
        object_id: IdentityKey,
        email: Optional[str] = None,
        name: Optional[str] = None,
        firstname: Optional[str] = None,
        lastname: Optional[str] = None,
        fullname: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        """
        Update an existing identity's information.

        Updates the specified identity record with new information.

        Args:
            object_id (IdentityKey): The object ID of the identity to update
            email (Optional[str]): New email address (converted to lowercase)
            name (Optional[str]): New name (aliases to firstname parameter)
            firstname (Optional[str]): New first name (aliases to name parameter)
            lastname (Optional[str]): New last name
            fullname (Optional[str]): New full name
            password (Optional[str]): New password to encode and store

        Edge Cases:
        - Email addresses are automatically converted to lowercase
        - If both name and firstname are provided, name takes precedence
        - Password is securely hashed before storage (if provided)
        - Only provided fields are updated; others retain their current values
        - Invalid object_id will raise an exception from get_identity
        """

        user = model.get_identity(self.db, object_id)
        user.update_record(
            email=email.lower().strip() if email else user.email,
            firstname=name if name else firstname if firstname else user.firstname,
            lastname=lastname if lastname else user.lastname,
            fullname=fullname if fullname else user.fullname,
            password=Password.encode(password) if password else user.encoded_password,
        )
        # self.# db.commit()

    def get_user(
        self, key: IdentityKey, return_memberships: bool = False
    ) -> UserDict | None:
        """
        Retrieve a user identity by key.

        Looks up a user by email, ID, UUID, or name and returns user information.

        Args:
            key (IdentityKey): Key to look up the user (email, ID, UUID, or name)
            return_memberships (bool): Whether to include membership information (default: False)

        Returns:
            UserDict | None: Dictionary containing user information, or None if not found

        Edge Cases:
        - Key lookup supports multiple formats (email, ID, UUID, name)
        - Email addresses are case-insensitive
        - If return_memberships is True, includes recursive group memberships
        - Returns None if user is not found
        - Invalid keys may raise ValueError from key lookup
        """

        if not (rec := model.get_user(self.db, key)):
            return None

        result: UserDict = dict(
            object_id=rec.object_id,
            email=rec.email,
            firstname=rec.firstname,
            fullname=rec.fullname,
        )
        if return_memberships:
            result["memberships"] = [
                dict(
                    object_id=m.object_id,
                    object_type=m.object_type,
                    email=m.email,
                    firstname=m.firstname,
                    fullname=m.fullname,
                )
                for m in model.get_memberships(self.db, rec.object_id, bare=False)
            ]
        return result

    def get_group(self, key, return_members=True) -> GroupDict | None:
        """
        Retrieve a group identity by key.

        Looks up a group by name, ID, UUID, or email and returns group information.

        Args:
            key: Key to look up the group (name, ID, UUID, or email)
            return_members (bool): Whether to include member information (default: True)

        Returns:
            GroupDict | None: Dictionary containing group information, or None if not found

        Edge Cases:
        - Key lookup supports multiple formats (name, ID, UUID, email)
        - Email addresses are case-insensitive
        - If return_members is True, includes recursive group members
        - Returns None if group is not found
        - Invalid keys may raise ValueError from key lookup
        """

        if not (group_rec := model.get_group(self.db, key)):
            return None

        members = []
        if return_members:
            members = model.get_members(self.db, group_rec.object_id, bare=False)
            members = [
                dict(
                    object_id=member.object_id,
                    object_type=member.object_type,
                    email=member.email,
                    name=member.firstname,
                )
                for member in members
            ]

        result: GroupDict = dict(
            object_id=group_rec.object_id,
            email=group_rec.email,
            name=group_rec.firstname,
        )
        if return_members:
            result["members"] = members
        return result

    def authenticate_user(self, key: IdentityKey, password: str) -> bool:
        """
        Authenticate a user by validating their password.

        Checks if a provided password matches the stored encoded password for a user.

        Args:
            key (IdentityKey): Key to look up the user (email, ID, UUID, or name)
            password (str): Password to validate

        Returns:
            bool: True if authentication is successful, False otherwise

        Edge Cases:
        - Uses constant-time comparison to prevent timing attacks
        - Returns False if user is not found or password is invalid
        """

        return model.authenticate_user(self.db, key=key, password=password)

    def add_membership(self, identity_key: IdentityKey, group_key: IdentityKey) -> None:
        """
        Add a membership relationship between an identity and a group.

        Creates a direct membership relationship where an identity
        (user, group, or item) becomes a member of a group.

        Args:
            identity_key (IdentityKey): The identity that will become a member of the group
            group_key (IdentityKey): The group that the identity will join

        Edge Cases:
        - If the membership already exists, it is silently ignored
        - Both identity and group must exist in the database
        - Invalid identity or group keys raise ValueError
        - Uses key_lookup with strict=True, so ambiguous lookups raise exceptions
        """

        return model.add_membership(self.db, identity_key, group_key)

    def remove_membership(
        self, identity_key: IdentityKey, group_key: IdentityKey
    ) -> int:
        """
        Remove a membership relationship between an identity and a group.

        Deletes an existing direct membership relationship.

        Args:
            identity_key (IdentityKey): The identity whose membership should be removed
            group_key (IdentityKey): The group from which the identity should be removed

        Returns:
            int: The number of membership records deleted (0 or 1)

        Edge Cases:
        - Returns 0 if the membership relationship doesn't exist
        - Both identity and group must exist in the database
        - Invalid identity or group keys raise exceptions from get_identity/get_group
        - Only removes direct memberships, not recursive ones
        """

        return model.remove_membership(self.db, identity_key, group_key)

    def has_membership(
        self, user_or_group_key: IdentityKey, group_key: IdentityKey
    ) -> bool:
        """
        Check if an identity is a member of a group.

        Determines whether a user or group is a member of the specified group,
        considering both direct and indirect memberships through group nesting.

        Args:
            user_or_group_key (IdentityKey): The user or group to check for membership
            group_key (IdentityKey): The group to check membership in

        Returns:
            bool: True if the identity is a member of the group, False otherwise

        Edge Cases:
        - Uses recursive membership views to check indirect memberships
        - Invalid keys may raise ValueError from key_lookup
        - Returns False if either identity or group is not found
        """

        key = key_lookup(self.db, user_or_group_key)
        group = key_lookup(self.db, group_key)
        memberships = (
            m.object_id for m in model.get_memberships(self.db, key, bare=False)
        )
        return group in memberships

    def add_permission(
        self,
        identity_key: IdentityKey,
        target_oid: IdentityKey,
        privilege: str,
        starts: When = DEFAULT_STARTS,
        ends: When = DEFAULT_ENDS,
    ) -> None:
        """
        Grant a permission to an identity on a target object with time bounds.

        Creates a permission record granting a specific privilege to
        an identity (user or group) on a target object, with optional start and end times.

        Args:
            identity_key (IdentityKey): The identity being granted permission
            target_oid (IdentityKey): The target object for the permission
            privilege (str): The privilege being granted (e.g., "read", "write")
            starts (When): When the permission becomes active (default: DEFAULT_STARTS)
            ends (When): When the permission expires (default: DEFAULT_ENDS)

        Edge Cases:
        - If permission already exists for the same identity, target, and privilege at the start time, it's skipped
        - Identity must exist in the database
        - Target doesn't need to exist in the database (can be any UUID)
        - Time bounds are parsed if provided as strings
        - Duplicate permissions are silently ignored
        """

        starts = unstr_datetime(starts)
        ends = unstr_datetime(ends)
        return model.add_permission(
            self.db, identity_key, target_oid, privilege, starts, ends
        )

    def add_permissions(
        self,
        identity_key: IdentityKey,
        target_oid: IdentityKey,
        privileges: typing.Iterable[str],
        starts: When = DEFAULT_STARTS,
        ends: When = DEFAULT_ENDS,
    ) -> None:
        """
        Grant multiple permissions to an identity on a target object with time bounds.

        Creates permission records granting multiple privileges to
        an identity (user or group) on a target object.

        Args:
            identity_key (IdentityKey): The identity being granted permissions
            target_oid (IdentityKey): The target object for the permissions
            privileges (typing.Iterable[str]): The privileges being granted
            starts (When): When the permissions become active (default: DEFAULT_STARTS)
            ends (When): When the permissions expire (default: DEFAULT_ENDS)

        Edge Cases:
        - Each permission is added individually with the same time bounds
        - If any permission already exists, it's skipped
        - Identity must exist in the database
        - Target doesn't need to exist in the database (can be any UUID)
        - Time bounds are parsed if provided as strings
        """

        for privilege in privileges:
            self.add_permission(identity_key, target_oid, privilege, starts, ends)

    def has_permission(
        self,
        identity_key: IdentityKey,
        target_oid: IdentityKey,
        privilege: str,
        when: Optional[When] = None,
    ) -> bool:
        """
        Check if an identity has a specific permission on a target object at a given time.

        Determines whether a user or group has been granted a specific privilege
        on a target object, considering both direct permissions and permissions inherited
        through group memberships. It also takes into account time-based permission validity.

        Args:
            identity_key (IdentityKey): The user or group whose permissions are being checked
            target_oid (IdentityKey): The target object for which permission is being checked
            privilege (str): The privilege to check for (e.g., "read", "write")
            when (Optional[When]): The time at which to check permissions (default: current time)

        Returns:
            bool: True if the identity has the specified permission on the target, False otherwise

        Edge Cases:
        - Uses recursive membership views to check permissions inherited through group nesting
        - Supports wildcard permissions (privilege "*") that grant all privileges
        - Time bounds are checked to ensure permissions are active at the specified time
        - If when is None, current time is used for the check
        - Invalid identity_key raises exception from key_lookup
        - Non-existent target_oid is handled gracefully and used as-is
        """

        when = DEFAULT if when is None else unstr_datetime(when)
        return model.has_permission(self.db, identity_key, target_oid, privilege, when)

    def remove_permission(
        self,
        identity_key: IdentityKey,
        target_oid: IdentityKey,
        privilege: str,
        when: Optional[When] = None,
    ) -> bool:
        """
        Revoke a permission from an identity on a target object.

        Removes an existing permission record based on identity, target,
        privilege, and time constraints. It deletes permissions that are active at
        the specified time.

        Args:
            identity_key (IdentityKey): The identity whose permission should be revoked
            target_oid (IdentityKey): The target object for which permission is revoked
            privilege (str): The privilege being revoked
            when (Optional[When]): The time at which to check for active permissions (default: current time)

        Returns:
            bool: True if a permission was found and removed, False otherwise

        Edge Cases:
        - Only removes permissions that are active at the specified time
        - Returns False if no matching permission is found
        - Uses exact matching on identity, target, and privilege
        - Time bounds are considered when determining active permissions
        - If when is None, current time is used for the check
        """

        when = DEFAULT if when is None else unstr_datetime(when)
        return model.remove_permission(
            self.db, identity_key, target_oid, privilege, when=when
        )
