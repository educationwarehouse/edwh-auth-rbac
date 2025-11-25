"""
Functions for managing Role-Based Access Control (RBAC) database tables and views.

This module includes functions to define and manage the database schema
for tables and views used in Role-Based Access Control, such as creating
tables for identity, membership, and permission, as well as views for
recursive relationships.

Functions:
- rbac_tables: Creates the RBAC-related tables in the database.
- rbac_views: Creates the RBAC-related recursive views in the database.
"""

from edwh_migrate import migration
from pydal import DAL


@migration()
def rbac_tables(db: DAL):
    """
    Defines the rbac_tables function, which creates database tables
    necessary for implementing role-based access control (RBAC) system functionality.
    This includes the 'identity', 'membership', and 'permission' tables.

    Parameters:
        db (DAL): The database abstraction layer instance used to execute SQL commands.

    Returns:
        bool: The status indicating successful execution of the table creation process.
    """
    db.executesql(
        """
        CREATE TABLE "identity" (
                                    "id"               SERIAL PRIMARY KEY,
                                    "object_id"        VARCHAR(36) NOT NULL UNIQUE,
                                    "object_type"      VARCHAR(512),
                                    "created"          TIMESTAMP,
                                    "email"            VARCHAR(512),
                                    "firstname"        VARCHAR(512),
                                    "lastname"         VARCHAR(512),
                                    "fullname"         VARCHAR(512),
                                    "encoded_password" VARCHAR(512)
                                );
        """,
    )

    # Create membership table
    db.executesql(
        """
        CREATE TABLE "membership" (
                                      "id"        SERIAL PRIMARY KEY,
                                      "subject"   VARCHAR(36) NOT NULL,
                                      "member_of" VARCHAR(36) NOT NULL
                                  );
        """,
    )

    # Create permission table
    db.executesql(
        """
        CREATE TABLE "permission" (
                                      "id"                 SERIAL PRIMARY KEY,
                                      "privilege"          VARCHAR(20),
                                      "identity_object_id" VARCHAR(36),
                                      "target_object_id"   VARCHAR(36),
                                      "starts"             char(35),
                                      "ends"               char(35)
                                  );
        """,
    )

    db.commit()

    return True


def wipe_views(db: DAL):
    db.executesql(
        """
        DROP VIEW IF EXISTS recursive_memberships;
        """,
    )
    db.executesql(
        """
        DROP VIEW IF EXISTS recursive_members;
        """,
    )


@migration()
def rbac_views(db: DAL):
    """
    Defines a migration function that manipulates database views for role-based access
    control (RBAC) using recursive queries. It creates or re-creates specific database
    views: `recursive_memberships` and `recursive_members`. These views facilitate the
    handling of hierarchical relationships and membership structures.

    Args:
        db (DAL): The database abstraction layer that enables executing SQL queries
        and managing the database.

    Returns:
        bool: True upon successful completion of the migration.
    """
    wipe_views(db)

    #
    db.executesql(
        """
        CREATE VIEW recursive_memberships AS
            -- Recursive view that finds all groups/roles that an identity is member of (directly or indirectly)
            -- For example: if User A is member of Group B, and Group B is member of Group C,
            -- then this view will show that User A is member of both Group B and Group C
            -- The 'level' indicates the depth of the membership chain (0 = direct membership)
            WITH
                RECURSIVE m(root, object_id, object_type, level, email, firstname, fullname) AS (
                -- Base case: start with each identity being member of itself (level 0)
                SELECT object_id AS root
                     , object_id
                     , object_type
                     , 0
                     , email
                     , firstname
                     , fullname
                    FROM identity
                UNION ALL
                -- Recursive case: find parent groups/roles through membership table
                -- For each membership found, increment the level and keep the original root
                SELECT root, membership.member_of, i.object_type, m.level + 1, i.email, i.firstname, i.fullname
                    FROM membership
                             JOIN m ON subject = m.object_id
                             JOIN identity i ON i.object_id = membership.member_of
                -- order by root, m.level+1
            )
            SELECT *
                FROM m
        ;
        """,
    )

    db.executesql(
        """
        CREATE VIEW recursive_members AS
            -- Recursive view that finds all members of a group/role (directly or indirectly)
            -- For example: if Group C contains Group B, and Group B contains User A,
            -- then this view will show that Group C contains both Group B and User A
            -- The 'level' indicates the depth of the membership chain (0 = direct membership)
            WITH
                RECURSIVE m(root, object_id, object_type, level, email, firstname, fullname) AS (
                -- Base case: start with each identity being a member of itself (level 0)
                SELECT object_id AS root
                     , object_id
                     , object_type
                     , 0
                     , email
                     , firstname
                     , fullname
                    FROM identity
                UNION ALL
                -- Recursive case: find child members through membership table
                -- For each member found, increment the level and keep the original root
                SELECT root, membership.subject, i.object_type, m.level + 1, i.email, i.firstname, i.fullname
                    FROM membership
                             JOIN m ON member_of = m.object_id
                             JOIN identity i ON i.object_id = membership.subject
                -- order by root
            )
            SELECT *
                FROM m;
        """,
    )

    db.commit()
    return True


@migration()
def rbac_varchar36_to_uuid(db: DAL):
    wipe_views(db)

    db.executesql("""
                  -- Convert identity.object_id from VARCHAR(36) to UUID
                  ALTER TABLE identity
                      ALTER COLUMN object_id TYPE uuid
                          USING object_id::uuid;

                  -- Convert membership.subject and membership.member_of
                  ALTER TABLE membership
                      ALTER COLUMN subject TYPE uuid
                          USING subject::uuid,
                      ALTER COLUMN member_of TYPE uuid
                          USING member_of::uuid;

                  -- Convert permission.identity_object_id and permission.target_object_id
                  ALTER TABLE permission
                      ALTER COLUMN identity_object_id TYPE uuid
                          USING identity_object_id::uuid,
                      ALTER COLUMN target_object_id TYPE uuid
                          USING target_object_id::uuid;
                  """)

    # rebuild view:
    rbac_views(db)

    db.commit()
    return True


@migration()
def rbac_treeview(db: DAL):
    db.executesql("""
    CREATE OR REPLACE FUNCTION rbac_tree(root_email TEXT DEFAULT NULL)
        RETURNS TABLE (
            tree TEXT,
            object_type VARCHAR,
            email VARCHAR
        ) AS $$
        BEGIN
            RETURN QUERY
            WITH RECURSIVE member_tree AS (
                -- Base case: Start with specified root or all root groups
                SELECT
                    i.object_id,
                    i.email,
                    COALESCE(i.fullname, i.firstname) AS display_name,
                    i.object_type,
                    0 AS depth,
                    ARRAY[i.object_id] AS id_path,
                    i.email::text AS sort_path
                FROM identity i
                WHERE (
                    -- If root_email is specified, start from that identity
                    (root_email IS NOT NULL AND i.email = root_email)
                    OR
                    -- Otherwise, start from all root groups (those not members of anything)
                    (root_email IS NULL
                     AND NOT EXISTS (SELECT 1 FROM membership m WHERE m.subject = i.object_id)
                     AND i.object_type = 'group')
                )

                UNION ALL

                -- Recursive case: Find all direct members
                SELECT
                    i.object_id,
                    i.email,
                    COALESCE(i.fullname, i.firstname) AS display_name,
                    i.object_type,
                    mt.depth + 1,
                    mt.id_path || i.object_id,
                    mt.sort_path || '|' || i.email::text
                FROM identity i
                JOIN membership m ON i.object_id = m.subject
                JOIN member_tree mt ON m.member_of = mt.object_id
                WHERE NOT (i.object_id = ANY(mt.id_path))
            )
            SELECT
                REPEAT('^', depth) || ' ' || display_name AS tree,
                member_tree.object_type,
                member_tree.email
            FROM member_tree
            ORDER BY sort_path, member_tree.object_type DESC, display_name;
        END;
        $$ LANGUAGE plpgsql;

        -- examples:
        -- select * from rbac_tree()
        -- select * from rbac_tree('members@internal')
    """)

    db.commit()
    return True

@migration()
def rbac_add_default_permission_starts_ends_20251125_001(db: DAL):
    db.executesql("""
    ALTER TABLE permission
        ALTER COLUMN starts SET DEFAULT '2000-01-01 00:00:00',
        ALTER COLUMN starts SET NOT NULL,
        ALTER COLUMN ends SET DEFAULT '3000-01-01 00:00:00',
        ALTER COLUMN ends SET NOT NULL;
    """)
    db.commit()
    return True