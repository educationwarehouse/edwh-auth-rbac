import os
import tempfile
import uuid
from pathlib import Path

import dotmap
import pytest
from pydal import DAL

from src.edwh_auth_rbac.migrations import rbac_views
from src.edwh_auth_rbac.model import define_auth_rbac_model
from src.edwh_auth_rbac.rbac import AuthRbac

namespace = uuid.UUID("84f5c757-4be0-49c8-a3ba-4f4d79167839")

FAKE_TEMPDIR = False


# FAKE_TEMPDIR = True


@pytest.fixture(scope="module")
def tmpdir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        if FAKE_TEMPDIR:
            fake = Path("/tmp/fake_tmpdir")
            fake.mkdir(exist_ok=True, parents=True)
            yield str(fake)
        else:
            print("new tempdir")
            yield tmpdirname


@pytest.fixture(scope="module")
def database(tmpdir):
    class Database:
        def __enter__(self):
            self.db = DAL("sqlite://auth_rbac.sqlite", folder=tmpdir)

            settings = dict(allowed_types=["user", "group", "item"], migrate=True)

            define_auth_rbac_model(self.db, settings)
            rbac_views(self.db)
            return self.db

        def __exit__(self, exc_type, exc_value, traceback):
            self.db.close()

    return Database()


@pytest.fixture(scope="module")
def rbac(database):
    with database as db:
        yield AuthRbac(db)


@pytest.fixture(scope="module")
def store(_=dotmap.DotMap()):
    print("store", _)
    return _


@pytest.mark.incremental
class TestSequentially:
    def test_drop_all_test_users(self, database):
        with database as db:
            users = db(db.identity.email.contains("@test.nl")).select()
            db(db.identity.email.contains("@test.nl")).delete()
            for user in users:
                db(
                    (db.membership.member_of == user.object_id)
                    | (db.membership.subject == user.object_id)
                ).delete()
                db(
                    (db.permission.identity_object_id == user.object_id)
                    | (db.permission.target_object_id == user.object_id)
                ).delete()
            db.commit()
            assert db(db.identity.email.contains("@test.nl")).count() == 0, (
                "Howcome @test.nl still exist?"
            )

    def test_user_creation(self, rbac, store):
        store.remco = rbac.add_user(
            "remco@test.nl", "remco", "remco test", "secret", []
        )["object_id"]
        store.pietje = rbac.add_user(
            "pietje@test.nl", "pietje", "pietje test", "secret", []
        )["object_id"]
        store.truus = rbac.add_user(
            "truus@test.nl", "truus", "truus test", "secret", []
        )["object_id"]

    def test_group_creation(self, rbac, store):
        store.groups = rbac.add_group("groups@test.nl", "groups", [])

        store.articles = rbac.add_group("articles@test.nl", "articles", [store.groups])[
            "object_id"
        ]
        store.all = rbac.add_group("all@test.nl", "all", [store.groups])["object_id"]
        store.users = rbac.add_group("users@test.nl", "users", [store.groups])[
            "object_id"
        ]
        store.admins = rbac.add_group("admins@test.nl", "admins", [store.groups])[
            "object_id"
        ]

        assert rbac.has_membership(store.admins, store.groups)
        assert not rbac.has_membership(store.groups, store.admins)

    def test_item_creation(self, rbac, store):
        for name in "abcde":
            store[name] = rbac.add_user(
                "article_" + name + "@test.nl", name, "article", "", []
            )["object_id"]

    def test_stash_users_in_groups(self, rbac, store):
        rbac.add_membership(store.remco, store.admins)
        rbac.add_membership(store.pietje, store.users)
        rbac.add_membership(store.truus, store.users)
        rbac.add_membership(store.users, store.all)
        rbac.add_membership(store.admins, store.all)

    def test_stash_items_in_groups(self, rbac, store):
        for name in "abcde":
            rbac.add_membership(store[name], store.articles)

    def test_add_some_permissions(self, rbac, store):
        rbac.add_permission(store.admins, store.articles, "read")
        rbac.add_permission(store.admins, store.articles, "write")
        rbac.add_permission(store.users, store.articles, "read")

    def test_first_level_memberships(self, rbac, store):
        assert rbac.has_membership(store.remco, store.admins) is True
        assert rbac.has_membership(store.pietje, store.users) is True
        assert rbac.has_membership(store.remco, store.users) is False
        assert rbac.has_membership(store.pietje, store.admins) is False

    def test_second_level_memberships(self, rbac, store):
        assert rbac.has_membership(store.remco, store.all) is True
        assert rbac.has_membership(store.pietje, store.all) is True

    def test_first_level_permissions(self, rbac, store):
        assert rbac.has_permission(store.admins, store.articles, "read") is True
        assert rbac.has_permission(store.admins, store.articles, "write") is True
        assert rbac.has_permission(store.users, store.articles, "read") is True
        assert rbac.has_permission(store.users, store.articles, "write") is False

    def test_second_to_first_level_permissions(self, rbac, store):
        assert rbac.has_permission(store.remco, store.articles, "read") is True
        assert rbac.has_permission(store.remco, store.articles, "write") is True
        assert rbac.has_permission(store.pietje, store.articles, "read") is True
        assert rbac.has_permission(store.pietje, store.articles, "write") is False

    def test_second_to_second_level_permissions(self, rbac, store):
        assert rbac.has_permission(store.remco, store.a, "read") is True
        assert rbac.has_permission(store.remco, store.a, "write") is True
        assert rbac.has_permission(store.pietje, store.a, "read") is True
        assert rbac.has_permission(store.pietje, store.a, "write") is False

    def test_deeper_group_nesting(self, rbac, store):
        store.subadmins = rbac.add_group("sub_admins@test.nl", "subadmins", [])[
            "object_id"
        ]
        store.subarticles = rbac.add_group("sub_articles@test.nl", "subarticles", [])[
            "object_id"
        ]
        rbac.add_membership(store.subarticles, store.articles)
        rbac.add_membership(store.subadmins, store.admins)
        store.nested_admin = rbac.add_user(
            "nested_admin@test.nl", "nested_admin", "nested_admin test", "secret", []
        )["object_id"]
        rbac.add_membership(store.nested_admin, store.subadmins)
        for name in "stuvw":
            store[name] = rbac.add_user(
                "article_" + name + "@test.nl", name, "subarticle", "", []
            )["object_id"]
            rbac.add_membership(store[name], store.subarticles)
        assert rbac.has_permission(store.nested_admin, store.s, "read") is True

    def test_removing_a_nested_group(self, rbac, store):
        rbac.remove_membership(store.nested_admin, store.subadmins)
        assert rbac.has_permission(store.nested_admin, store.s, "read") is False

    def test_permission_flow(self, rbac):
        users = rbac.add_group("users@internal", "Users", [])
        items = rbac.add_group("items@internal", "Items", [])
        user = rbac.add_user("test@example", "Test", "Test Example", "secure", [users])
        item_gid = str(uuid.uuid4())

        item = rbac.add_item(f"@{item_gid}", item_gid, [items], gid=item_gid)

        assert item["object_id"] == item_gid

        rbac.add_permissions(users, item_gid, ["read"])

        assert rbac.has_permission(user, item_gid, "read")

        admins = rbac.add_group("admins@internal", "Admins", [users])
        rbac.add_permission(admins, item_gid, "*")

        admin1 = rbac.add_user(
            "admin1@example", "Admin1", "Admin One", "secure", [admins]
        )

        assert rbac.has_permission(admin1, item_gid, "read")
        assert rbac.has_permission(admin1, item_gid, "write")

        assert rbac.has_permission(user, item_gid, "read")
        assert not rbac.has_permission(user, item_gid, "write")

        # test add_permission with identity dict or email instead of only gid:
        id1 = rbac.add_identity(
            "id1@example",
            "id1",
            [],
            "item",
        )

        assert not rbac.has_permission(id1, id1, "read")

        rbac.add_permission(id1, id1, "read")

        assert rbac.has_permission(id1, id1, "read")

        assert not rbac.has_permission(id1, id1, "write")
        rbac.add_permission("id1@example", "id1@example", "write")
        assert rbac.has_permission(id1, id1, "write")

    def test_existing_uuids(self, rbac):
        assert (
            rbac.add_user(
                "c3@user",
                "c3",
                "c3 user",
                "verysecrets",
                [],
                gid="c3685794-5b9f-41d9-a7ec-d7efcd87d253",
            )["object_id"]
            == "c3685794-5b9f-41d9-a7ec-d7efcd87d253"
        )
        assert (
            rbac.add_group(
                "ec@group", "ec", [], gid="ecf43e58-a0ec-42fd-8634-bb498e2c4273"
            )["object_id"]
            == "ecf43e58-a0ec-42fd-8634-bb498e2c4273"
        )
        assert (
            rbac.add_item(
                "2d@item", "2d", [], gid="2d4d8ac4-921e-403f-be06-e34b353b4f43"
            )["object_id"]
            == "2d4d8ac4-921e-403f-be06-e34b353b4f43"
        )
