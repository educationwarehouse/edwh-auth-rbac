# edwh-auth-rbac

Role-Based Access Control (RBAC) library with recursive memberships for Python applications.

## Overview

This library implements a comprehensive RBAC system that supports:
- Users, groups, and items as identities
- Recursive group memberships (groups can contain other groups)
- Time-bound permissions with start/end dates
- Wildcard permissions (* for all privileges, all identities, or all targets)
- Password hashing with HMAC-SHA512 and per-entry random salts

## Mental Model

The system is built around three core concepts:

1. **Identities**: Users (people), Groups (collections), and Items (resources)
2. **Memberships**: Direct relationships between identities (who belongs to what)
3. **Permissions**: Granted privileges on targets with time constraints

## Key Features

- Recursive membership resolution through database views
- Efficient permission checking using JOINs with recursive membership views
- Flexible identity lookup by email, ID, UUID, or name
- Secure password storage with constant-time validation

## Installation

```bash
pip install edwh-auth-rbac
```

## Basic Usage
This requires a setup like the demo, see below for details, but this is how you would mostly use it in every day use: 

```python
from pydal import DAL
from edwh_auth_rbac import AuthRbac

# Initialize database
db = DAL('sqlite://storage.sqlite')

# Initialize RBAC
rbac = AuthRbac(db)
rbac.define_model(allowed_types=['user', 'group', 'item'], migrate=True)
```

### Creating Users and Groups

```python
# Create a group
admin_group = rbac.add_group(
    email="admin@example.com",
    name="Administrators",
    member_of=[]
)

# Create a user
user = rbac.add_user(
    email="john@example.com",
    firstname="John",
    fullname="John Doe",
    password="secure_password",
    member_of=[admin_group['object_id']]  # Add user to admin group
)
```

### Adding Permissions

```python
# Grant read permission to a user on a resource
rbac.add_permission(
    identity_key=user['object_id'],
    target_oid="document_123",
    privilege="read"
)

# Grant write permission to a group (affects all members)
rbac.add_permission(
    identity_key=admin_group['object_id'],
    target_oid="document_123",
    privilege="write"
)
```

### Checking Permissions

```python
# Check if user has permission
has_read = rbac.has_permission(
    identity_key=user['object_id'],
    target_oid="document_123",
    privilege="read"
)

print(f"User has read permission: {has_read}")
```

## Advanced Features

### Recursive Group Memberships

Groups can contain other groups, creating a hierarchy:

```python
# Create nested groups
root_group = rbac.add_group(email="root@example.com", name="Root", member_of=[])
middle_group = rbac.add_group(email="middle@example.com", name="Middle", member_of=[root_group['object_id']])
leaf_group = rbac.add_group(email="leaf@example.com", name="Leaf", member_of=[middle_group['object_id']])

# Add user to leaf group
user = rbac.add_user(
    email="user@example.com",
    firstname="User",
    fullname="Test User",
    password="password",
    member_of=[leaf_group['object_id']]
)

# User now has permissions granted to any of the parent groups
```

### Time-Bound Permissions

Permissions can be granted for specific time periods:

```python
import datetime as dt

rbac.add_permission(
    identity_key=user['object_id'],
    target_oid="document_123",
    privilege="read",
    starts=dt.datetime(2023, 1, 1),
    ends=dt.datetime(2023, 12, 31)
)
```

## Edge Cases and Assumptions

- **Circular group memberships** are prevented by the recursive view logic
- **Non-existent targets** in permissions are allowed (flexible resource modeling)
- **Time-bound permissions** with precise datetime validation
- **Wildcard permissions** that grant broad access rights (using "*")
- **Case-insensitive email handling**
- **Automatic cleanup** of related records when identities are removed
- Passwords are stored securely with HMAC-SHA512 and per-entry random salts
- Group names can be used as lookup keys for groups
- Email addresses needn't be unique across different identity types

### Setup demo database
For your own application, you'd probably want to use your own migration tool or use ours. But you'd have a list
of migrations where you will want to include these from the `src/edwh_auth_rbac/migrations.py` file

Prepare the migration:
```bash
cd your-demo-folder
mkdir flags
export MIGRATE_URI=sqlite://storage.sqlite
export FLAG_LOCATION=./flags
```
Execute the migration: 
```bash
$ migrate src/edwh_auth_rbac/migrations.py 
testing migrate lock file with the current version
Using lock file:  flags/migrate-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.complete
Using argument src/edwh_auth_rbac/migrations.py as a reference to the migrations file.
importing migrations from src/edwh_auth_rbac/migrations.py
starting migrate hook
2 migrations discovered
table not found, starting database restore
RECOVER: attempting recovery from a backup
RECOVER_DATABASE_FROM_BACKEND started 
RECOVER: /data/database_to_restore.NOTFOUND not found. Starting from scratch.
test: rbac_tables
run:  rbac_tables
ran:  rbac_tables successfully (0.01s wall, 0.00s CPU)
test: rbac_views
run:  rbac_views
ran:  rbac_views successfully (0.00s wall, 0.00s CPU)
migration completed successfully, marking success.
```

### Execute the example.py demo: 
```bash
$ python3 example.py 
=== Creating Users and Groups and Documents ===
Created document item: {'object_id': '208247a1-cf2f-4f4e-a0c9-3edc813a78b6', 'email': 'document@example.com', 'name': 'Test Document'}
Created admin group: {'object_id': '481c6a16-672f-43b7-ad71-2b1830a3dc09', 'email': 'admin@example.com', 'name': 'Administrators'}
Created user: {'object_id': 'c797b2da-47b4-42a4-ab1d-2c0b6150555f', 'email': 'john@example.com', 'firstname': 'John', 'fullname': 'John Doe'}

=== Adding Permissions ===
Granted read permission to user on document_123
Granted write permission to admin group on document_123

=== Checking Permissions ===
User has read permission: True
User has write permission: True

=== Example completed successfully! ===
```

## Database Schema

The library creates the following tables:
- `identity`: Core identity records with object_id, type, and credentials
- `membership`: Direct membership relationships between identities
- `permission`: Time-bound privilege grants from identity to target
- `recursive_memberships`: View showing all indirect memberships
- `recursive_members`: View showing all indirect members

## API Reference

For detailed API documentation, see the docstrings in the source code:
- `AuthRbac` class in `src/edwh_auth_rbac/rbac.py`
- Model functions in `src/edwh_auth_rbac/model.py`
