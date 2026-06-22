import tempfile

import pytest
from edwh_migrate import migrations as registered_migrations
from pydal import DAL
from testcontainers.postgres import PostgresContainer

DB_NAME = "edwh_rbac_test"

postgres = PostgresContainer("postgres:16-alpine", dbname=DB_NAME)


@pytest.fixture(scope="module", autouse=True)
def psql(request):
    # defer teardown:
    request.addfinalizer(postgres.stop)

    postgres.start()
    # note: ONE PostgresContainer with scope module can be used,
    # if you try to use containers in a function scope, it will not work.
    # thus, this clean_db fixture is added to cleanup between tests:


@pytest.fixture()
def conn_str():
    conn_str = postgres.get_connection_url()
    # make pydal-friendly:
    return "postgres://" + conn_str.split("://")[-1]


@pytest.fixture()
def tempdir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture()
def sqlite_db(tempdir: str):
    conn_str = f"sqlite://{DB_NAME}.sqlite"
    db = DAL(conn_str, migrate=False, folder=tempdir)
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def postgres_db(conn_str: str, tempdir: str):
    db = DAL(conn_str, migrate=False, folder=tempdir)
    try:
        yield db
    finally:
        db.close()


def test_sqlite_migrate(sqlite_db: DAL):
    from src.edwh_auth_rbac import migrations

    assert migrations.rbac_tables(sqlite_db)
    assert migrations.rbac_views(sqlite_db)


def test_postgres_migrate(postgres_db: DAL):
    for migration_name, migration in registered_migrations:
        assert migration(postgres_db)

    # assert recursive_memberships has an ID column now:
    postgres_db.executesql("""
         SELECT id
             FROM recursive_memberships
             LIMIT 1;
         """)


def test_recursive_refresh_matches_rebuild_semantics(postgres_db: DAL):
    postgres_db.commit()
    print("debug: dropping existing tables")
    postgres_db.executesql("""
        DROP TABLE IF EXISTS recursive_members CASCADE;
        DROP TABLE IF EXISTS recursive_memberships CASCADE;
        DROP TABLE IF EXISTS permission CASCADE;
        DROP TABLE IF EXISTS membership CASCADE;
        DROP TABLE IF EXISTS identity CASCADE;
    """)
    postgres_db.commit()

    print("debug: applying migrations")
    for migration_name, migration in registered_migrations:
        print(f"debug: migration {migration_name}")
        assert migration(postgres_db)

    print("debug: inserting identities and memberships")
    postgres_db.executesql("""
        INSERT INTO identity (object_id, object_type, email, firstname, fullname)
        VALUES
            ('00000000-0000-0000-0000-000000000001', 'user', 'u@example.com', 'U', 'User'),
            ('00000000-0000-0000-0000-000000000002', 'group', 'g2@example.com', 'G2', 'Group 2'),
            ('00000000-0000-0000-0000-000000000003', 'group', 'g3@example.com', 'G3', 'Group 3'),
            ('00000000-0000-0000-0000-000000000004', 'group', 'g4@example.com', 'G4', 'Group 4');

        INSERT INTO membership (subject, member_of)
        VALUES
            ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002'),
            ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000003'),
            ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000004'),
            ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000004');
    """)

    print("debug: selecting rows before rebuild")
    before_rebuild = postgres_db.executesql("""
        SELECT root::text, object_id::text, level
        FROM recursive_memberships
        WHERE root = '00000000-0000-0000-0000-000000000001'::uuid
        ORDER BY object_id, level;
    """)
    print(f"debug: before rebuild rows = {before_rebuild}")

    print("debug: calling rebuild_recursive_tables()")
    postgres_db.executesql("SELECT rebuild_recursive_tables()")

    print("debug: selecting rows after rebuild")
    after_rebuild = postgres_db.executesql("""
        SELECT root::text, object_id::text, level
        FROM recursive_memberships
        WHERE root = '00000000-0000-0000-0000-000000000001'::uuid
        ORDER BY object_id, level;
    """)
    print(f"debug: after rebuild rows = {after_rebuild}")

    assert before_rebuild == after_rebuild
    assert after_rebuild == [
        ("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000001", 0),
        ("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", 1),
        ("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000003", 1),
        ("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000004", 2),
    ]
