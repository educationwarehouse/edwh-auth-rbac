from edwh_migrate import migration


@migration()
def rbac_migrations(db):
    db.executesql("""
    drop view if exists recursive_memberships;
    """)
    db.executesql("""
create view recursive_memberships as
  -- each root is member of object_id, including one line for himself.
  -- also for a user
  with RECURSIVE m(root, object_id, object_type, level, email, firstname, fullname) as (
        select object_id as root,  object_id, object_type, 0, email, firstname, fullname
          from identity
        union all
        select root, membership.member_of, i.object_type, m.level+1, i.email, i.firstname, i.fullname
          from membership join m on subject == m.object_id
               join identity i on i.object_id = membership.member_of
        order by root, m.level+1
    )
    select * from m
;
""")

    db.executesql("""
drop view if exists recursive_members;
    
    """)

    db.executesql("""
create view recursive_members as
    with RECURSIVE m(root, object_id, object_type, level, email, firstname, fullname) as (
        select object_id as root, object_id, object_type, 0, email, firstname, fullname
          from identity
        union all
        select root, membership.subject, i.object_type, m.level+1, i.email, i.firstname, i.fullname
          from membership join m on member_of== m.object_id
               join identity i on i.object_id = membership.subject
        order by root
    )
    select * from m
;

    """)

    db.commit()
    return True
