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
        CREATE TABLE "identity"(
            "id" SERIAL PRIMARY KEY,
            "object_id" VARCHAR(36) NOT NULL UNIQUE,
            "object_type" VARCHAR(512),
            "created" TIMESTAMP,
            "email" VARCHAR(512),
            "firstname" VARCHAR(512),
            "lastname" VARCHAR(512),
            "fullname" VARCHAR(512),
            "encoded_password" VARCHAR(512)
        );
        """
    )

    # Create membership table
    db.executesql(
        """
        CREATE TABLE "membership"(
            "id" SERIAL PRIMARY KEY,
            "subject" VARCHAR(36) NOT NULL,
            "member_of" VARCHAR(36) NOT NULL
        );
        """
    )

    # Create permission table
    db.executesql(
        """
        CREATE TABLE "permission"(
            "id" SERIAL PRIMARY KEY,
            "privilege" VARCHAR(20),
            "identity_object_id" VARCHAR(36),
            "target_object_id" VARCHAR(36),
            "starts" char(35),
            "ends" char(35)
        );
        """
    )

    db.commit()

    return True


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
    db.executesql(
        """
    drop view if exists recursive_memberships;
    """
    )
    # 
    db.executesql(
        """
create view recursive_memberships as
    -- Recursive view that finds all groups/roles that an identity is member of (directly or indirectly)
    -- For example: if User A is member of Group B, and Group B is member of Group C,
    -- then this view will show that User A is member of both Group B and Group C
    -- The 'level' indicates the depth of the membership chain (0 = direct membership)
with
    RECURSIVE
    m(root, object_id, object_type, level, email, firstname, fullname) as (
        -- Base case: start with each identity being member of itself (level 0)
        select
            object_id as root
          , object_id
          , object_type
          , 0
          , email
          , firstname
          , fullname
            from
                identity
        union all
        -- Recursive case: find parent groups/roles through membership table
        -- For each membership found, increment the level and keep the original root
        select root, membership.member_of, i.object_type, m.level+1, i.email, i.firstname, i.fullname
          from membership join m on subject = m.object_id
               join identity i on i.object_id = membership.member_of
        -- order by root, m.level+1
    )
    select * from m
;
"""
    )

    db.executesql(
        """
drop view if exists recursive_members;
    
    """
    )

    db.executesql(
        """
create view recursive_members as
    -- Recursive view that finds all members of a group/role (directly or indirectly)
    -- For example: if Group C contains Group B, and Group B contains User A,
    -- then this view will show that Group C contains both Group B and User A
    -- The 'level' indicates the depth of the membership chain (0 = direct membership)
with
    RECURSIVE
    m(root, object_id, object_type, level, email, firstname, fullname) as (
        -- Base case: start with each identity being a member of itself (level 0)
        select
            object_id as root
          , object_id
          , object_type
          , 0
          , email
          , firstname
          , fullname
            from
                identity
        union all
        -- Recursive case: find child members through membership table
        -- For each member found, increment the level and keep the original root
        select root, membership.subject, i.object_type, m.level+1, i.email, i.firstname, i.fullname
          from membership join m on member_of = m.object_id
               join identity i on i.object_id = membership.subject
        -- order by root
    )
    select * from m
;

    """
    )

    db.commit()
    return True


@migration()
def rbac_varchar36_to_uuid(db: DAL):
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

    db.commit()
    return True
