# debug performance of rbac functionality on a production-like database with a lot of identities:
# edwh devdb.snapshot --include identity --include ewh_implemented_features --include membership --include permission --include recursive_memberships --include recursive_members --name trimmed
# docker compose run --rm migrate python src/performance.py
import functools
import os
import time

from pydal import DAL
from termcolor import cprint

from edwh_auth_rbac import AuthRbac


class TimedProxy[T]:
    def __init__(self, obj: T, thresh: int = 100):
        self._obj = obj
        self._threshold = thresh
        self._start = time.perf_counter()

    def __getattr__(self, name):
        attr = getattr(self._obj, name)
        if callable(attr):

            @functools.wraps(attr)
            def timed_call(*args, **kwargs):
                start = time.perf_counter()
                result = attr(*args, **kwargs)
                duration_ms = (time.perf_counter() - start) * 1000
                if duration_ms > self._threshold:
                    cprint(f"{name} took {duration_ms:.2f}ms", "red")
                else:
                    print(f"{name} took {duration_ms:.2f}ms")
                return result

            return timed_call
        return attr

    def total(self):
        duration_ms = (time.perf_counter() - self._start) * 1000
        cprint(f"Total took {duration_ms:.2f}ms", "blue")


def timed[T](cls: T, **kw) -> T:
    return TimedProxy(cls, **kw)


def main():
    db = DAL(os.environ["MIGRATE_URI"])
    rbac = timed(AuthRbac(db), thresh=50)

    rbac.define_model(allowed_types=["user", "group", "item"], migrate=False)

    me = rbac.get_user("0c111158-15bc-456d-8057-b8c7cb9fa7bb")
    assert me

    admins = rbac.get_group("admin@internal")  # ~ 200ms
    assert admins

    assert rbac.has_membership(me, admins)

    non_admin = rbac.get_user("a5797696-36eb-4153-a1ca-694dfcc61c62")
    assert non_admin

    assert not rbac.has_membership(non_admin, admins)

    user_organisation = rbac.get_identity("dd5cfbf0-1a21-41ca-b21a-25baa21ecebe")
    assert user_organisation

    assert rbac.has_membership(non_admin, user_organisation.object_id)

    example_item = rbac.get_identity("378d3b39-1f21-4810-91c2-5847f1ceee2c")

    assert rbac.has_permission(user_organisation.object_id, example_item.object_id, "*")  # ~60ms
    assert rbac.has_permission(non_admin, example_item.object_id, "*")  # ~60ms

    assert len(rbac.get_permissions(non_admin)) == 2

    db.executesql("""
    DELETE FROM identity where email like '%@performance';
    """)

    new_group = rbac.add_group("newgroup@performance", "new group", [])
    new_user = rbac.add_identity("user@performance", "new user", [new_group], "user")
    new_item = rbac.add_identity("item@performance", "new item", [], "item")

    rbac.add_permission(new_group, new_item, "read")
    assert rbac.has_permission(new_group, new_item, "read")
    assert rbac.has_permission(new_user, new_item, "read")

    print(f"all assertions seem fine")
    rbac.total()

    # sorted_timings = sorted((
    #     (query[:100], ms) for query, ms in db._timings
    #     if ms > 0.1
    # ), key=lambda x: x[1], reverse=True)
    # print(
    #     tabulate(
    #         sorted_timings,
    #         headers=['call', 'ms'],
    #         floatfmt='.2f',
    #         tablefmt='grid',
    #     )
    # )


if __name__ == "__main__":
    main()
