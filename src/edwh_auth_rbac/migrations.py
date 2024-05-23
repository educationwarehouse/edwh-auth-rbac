from edwh_migrate import migration
from pydal import DAL


@migration()
def rbac_tables(db: DAL):
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
    db.executesql(
        """
    drop view if exists recursive_memberships;
    """
    )
    db.executesql(
        """
create view recursive_memberships as
  -- each root is member of object_id, including one line for himself.
  -- also for a user
  with RECURSIVE m(root, object_id, object_type, level, email, firstname, fullname) as (
        select object_id as root,  object_id, object_type, 0, email, firstname, fullname
          from identity
        union all
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
    with RECURSIVE m(root, object_id, object_type, level, email, firstname, fullname) as (
        select object_id as root, object_id, object_type, 0, email, firstname, fullname
          from identity
        union all
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
