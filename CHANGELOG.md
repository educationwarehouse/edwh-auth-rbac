# Changelog

<!--next-version-placeholder-->

## v0.7.1 (2025-09-02)

### Fix

* **allow_existing:** Functions should return specificdicts, not the raw records ([`a2eb929`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/a2eb929b4034c1b52885c0e29819856b2ee6a797))

## v0.7.0 (2025-09-02)

### Feature

* Support `allow_existing` for multiple `add_` function to prevent error on conflict ([`07c5eae`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/07c5eae03696bab07517b3e22283c22c4cfa15a9))

## v0.6.0 (2024-06-06)

### Feature

* `add_permissions` to bulk add privileges ([`6eb08e6`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/6eb08e6a36ceca93847f40cf1d92205553193452))

## v0.5.0 (2024-06-03)

### Feature

* Improved add_permission and has_permission: target_key will now also be looked up (without ValueError on missing key) ([`df388be`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/df388be6a497f0413c2f627dc8c289887b6d7385))

## v0.4.3 (2024-05-31)

### Fix

* Wildcards are only supported in 'privilege', not as object IDs to prevent confusion ([`6f2928e`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/6f2928e9e7807494d6a2a4add8cdf87263b7566b))

## v0.4.2 (2024-05-31)

### Fix

* Replace str.format with fstrings to catch missing variables ([`d9d6457`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/d9d64575f019a0d51573f17aef323805a05e4256))

## v0.4.1 (2024-05-30)

### Fix

* Memberhips -> memberships; get_ functions can return None ([`ebd7a0b`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/ebd7a0b4940af61e54639eab80cddb256662f239))

## v0.4.0 (2024-05-30)

### Feature

* Support BYOG (bring your own gid) for all relevant add_ functions (item, group, user; not membership, permission) ([`aeb06d9`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/aeb06d9ad7ba385c57fbc6836da878bd1775ae49))

## v0.3.0 (2024-05-29)

### Feature

* Allow '*' privileges ([`2980fe1`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/2980fe17038b456d7a101a4486499e3bd3e7a61b))

## v0.2.7 (2024-05-29)

### Fix

* Don't autocommit within this library; raise errors from validate_ result ([`b203e46`](https://github.com/educationwarehouse/edwh-auth-rbac/commit/b203e46380e3b0338375c5cbd978fcf6eec5c561))

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
