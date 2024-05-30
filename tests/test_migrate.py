import tempfile

import pytest
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


def test_sqlite_migrate(tempdir: str):
    from src.edwh_auth_rbac import migrations

    conn_str = f"sqlite://{DB_NAME}.sqlite"

    db = DAL(conn_str, migrate=False, folder=tempdir)

    assert migrations.rbac_tables(db)
    assert migrations.rbac_views(db)


def test_postgres_migrate(conn_str: str, tempdir: str):
    from src.edwh_auth_rbac import migrations

    db = DAL(conn_str, migrate=False, folder=tempdir)

    assert migrations.rbac_tables(db)
    assert migrations.rbac_views(db)
