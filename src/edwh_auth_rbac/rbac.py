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
    object_id: str
    email: str
    firstname: str
    fullname: str
    object_type: NotRequired[ObjectTypes]
    memberships: NotRequired[list["UserDict"]]


class GroupDict(typing.TypedDict):
    object_id: str
    email: str
    name: str
    members: NotRequired[list[MinimalIdentityDict]]


class AuthRbac:
    name = "auth_rbac"

    def __init__(self, db: DAL):
        self.db = db

    def define_model(self, **options: Unpack[RbacKwargs]):
        define_auth_rbac_model(self.db, options)

    @staticmethod
    def _error(msg):
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
        return model.authenticate_user(self.db, key=key, password=password)

    def add_membership(self, identity_key: IdentityKey, group_key: IdentityKey) -> None:
        return model.add_membership(self.db, identity_key, group_key)

    def remove_membership(
        self, identity_key: IdentityKey, group_key: IdentityKey
    ) -> int:
        return model.remove_membership(self.db, identity_key, group_key)

    def has_membership(
        self, user_or_group_key: IdentityKey, group_key: IdentityKey
    ) -> bool:
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
        for privilege in privileges:
            self.add_permission(identity_key, target_oid, privilege, starts, ends)

    def has_permission(
        self,
        identity_key: IdentityKey,
        target_oid: IdentityKey,
        privilege: str,
        when: Optional[When] = None,
    ) -> bool:
        when = DEFAULT if when is None else unstr_datetime(when)
        return model.has_permission(self.db, identity_key, target_oid, privilege, when)

    def remove_permission(
        self,
        identity_key: IdentityKey,
        target_oid: IdentityKey,
        privilege: str,
        when: Optional[When] = None,
    ) -> bool:
        when = DEFAULT if when is None else unstr_datetime(when)
        return model.remove_permission(
            self.db, identity_key, target_oid, privilege, when=when
        )
