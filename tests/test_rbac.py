import tempfile
import uuid

import dotmap
import pytest
from pydal import DAL

from src.edwh_auth_rbac.migrations import rbac_views
from src.edwh_auth_rbac.model import define_auth_rbac_model
from src.edwh_auth_rbac.rbac import AuthRbac

namespace = uuid.UUID("84f5c757-4be0-49c8-a3ba-4f4d79167839")


@pytest.fixture(scope="module")
def tmpdir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        print("new tempdir")
        yield tmpdirname


@pytest.fixture(scope="module")
def database(tmpdir):
    class Database:
        def __enter__(self):
            self.db = DAL("sqlite://auth_rbac.sqlite", folder=tmpdir)

            settings = dict(allowed_types=["user", "group"], migrate=True)

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
                db((db.membership.member_of == user.object_id) | (db.membership.subject == user.object_id)).delete()
                db(
                    (db.permission.identity_object_id == user.object_id)
                    | (db.permission.target_object_id == user.object_id)
                ).delete()
            db.commit()
            assert db(db.identity.email.contains("@test.nl")).count() == 0, "Howcome @test.nl still exist?"

    def test_user_creation(self, rbac, store):
        store.remco = rbac.add_user("remco@test.nl", "remco", "remco test", "secret", [])["object_id"]
        store.pietje = rbac.add_user("pietje@test.nl", "pietje", "pietje test", "secret", [])["object_id"]
        store.truus = rbac.add_user("truus@test.nl", "truus", "truus test", "secret", [])["object_id"]

    def test_group_creation(self, rbac, store):
        store.groups = rbac.add_group("groups@test.nl", "groups", [])

        store.articles = rbac.add_group("articles@test.nl", "articles", [store.groups])["object_id"]
        store.all = rbac.add_group("all@test.nl", "all", [store.groups])["object_id"]
        store.users = rbac.add_group("users@test.nl", "users", [store.groups])["object_id"]
        store.admins = rbac.add_group("admins@test.nl", "admins", [store.groups])["object_id"]

        assert rbac.has_membership(store.admins, store.groups)
        assert not rbac.has_membership(store.groups, store.admins)

    def test_item_creation(self, rbac, store):
        for name in "abcde":
            store[name] = rbac.add_user("article_" + name + "@test.nl", name, "article", "", [])["object_id"]

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
        store.subadmins = rbac.add_group("sub_admins@test.nl", "subadmins", [])["object_id"]
        store.subarticles = rbac.add_group("sub_articles@test.nl", "subarticles", [])["object_id"]
        rbac.add_membership(store.subarticles, store.articles)
        rbac.add_membership(store.subadmins, store.admins)
        store.nested_admin = rbac.add_user("nested_admin@test.nl", "nested_admin", "nested_admin test", "secret", [])[
            "object_id"
        ]
        rbac.add_membership(store.nested_admin, store.subadmins)
        for name in "stuvw":
            store[name] = rbac.add_user("article_" + name + "@test.nl", name, "subarticle", "", [])["object_id"]
            rbac.add_membership(store[name], store.subarticles)
        assert rbac.has_permission(store.nested_admin, store.s, "read") is True

    def test_removing_a_nested_group(self, rbac, store):
        rbac.remove_membership(store.nested_admin, store.subadmins)
        assert rbac.has_permission(store.nested_admin, store.s, "read") is False
