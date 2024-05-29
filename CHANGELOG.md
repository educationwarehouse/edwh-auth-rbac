# Changelog

<!--next-version-placeholder-->

## v0.2.6 (2024-05-29)

### Fix

* Make ruff happier ([`22b12e0`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/22b12e03d0556be64990544cfc16ef2fdc46f73a))
* You can provide a custom gid to add_identity/add_item and password is optional for items ([`986175b`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/986175b7be37aec8559c5d2130082533be15e31f))

## v0.2.5 (2024-05-27)

### Fix

* Allow `key_lookup` by whole row (e.g. dict with object_id and/or email) ([`03d5dd0`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/03d5dd041041261737f31b2bd0075312be0a68e3))

## v0.2.4 (2024-05-27)

### Fix

* Is_uuid now says True if the value already is a uuid.UUID; -> fixes `member_of` behavior ([`5030797`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/503079711fb2613c4df900020fc6625c94373d0b))

## v0.2.3 (2024-05-27)



## v0.2.3 (2024-05-27)

### Fix

* Auth_rbac.define_model() can be used instead of `define_auth_rbac_model` ([`fab9a5a`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/fab9a5a6272238566417b5dd46913e232ffa6776))

## v0.2.2 (2024-05-23)

### Fix

* Make migrations work for postgres (+ add tests for sqlite and psql) ([`a75758c`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/a75758c0851ed46e5e3e623a63073066f6d533f7))

## v0.2.1 (2024-05-22)

### Fix

* Those views are not tables ([`f2d8496`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/f2d84962bd3aa5bf87901d999f180ac1e9ffd815))

## v0.2.0 (2024-05-22)

### Feature

* Publish (postgres) migrations for rbac ([`5d00057`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/5d00057d16e58c87369be0658fa1c62032ea045b))

### Fix

* Improve typing ([`4a1eb6e`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/4a1eb6eec62350729b9e77719dc8426610e2d716))

## v0.1.1 (2024-05-21)

### Fix

* Don't ship venv, ship as edwh_auth_rbac not as src ([`e7a0d4d`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/e7a0d4de6361e941c28c1b3f81cbed1a13f48011))
* Make build actually work ([`57def49`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/57def49f6113f52ed5dffbf32fd01da906d56826))

## v0.1.0 (2024-05-16)

### Feature

* Initial non-nameko version ([`9a292ad`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/9a292ad3de3b7181f2cbcea8c227dbfccc1c4bc4))
