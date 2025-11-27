#!/usr/bin/env python3
"""
Example script demonstrating the usage of edwh-auth-rbac library.

This script showcases the basic functionality including:
- Setting up the RBAC system
- Creating identities (user, group and document)
- Managing permissions
- Checking permissions
- Working with recursive group memberships
"""

from pydal import DAL

from edwh_auth_rbac import AuthRbac


def main():
    # Initialize database
    db = DAL("sqlite://storage.sqlite")

    # Initialize RBAC
    rbac = AuthRbac(db)
    rbac.define_model(allowed_types=["user", "group", "item"])
    db.commit()
    print("=== Creating Users and Groups and Documents ===")

    # Create a document
    document_item = rbac.add_item(
        email="document@example.com",
        name="Test Document",
        member_of=[],
    )
    print(f"Created document item: {document_item}")

    # Create a group
    admin_group = rbac.add_group(email="admin@example.com", name="Administrators", member_of=[])
    print(f"Created admin group: {admin_group}")
    # Create a user
    user = rbac.add_user(
        email="john@example.com",
        firstname="John",
        fullname="John Doe",
        password="secure_password",
        member_of=[admin_group["object_id"]],  # Add user to admin group
    )
    print(f"Created user: {user}")

    print("\n=== Adding Permissions ===")

    # Grant read permission to a user on a resource
    rbac.add_permission(
        identity_key=user["object_id"],
        target_oid=document_item["object_id"],  # Use the actual document ID
        privilege="read",
    )
    print("Granted read permission to user on document_123")

    # Grant write permission to a group (affects all members)
    rbac.add_permission(
        identity_key=admin_group["object_id"],
        target_oid=document_item["object_id"],  # Use the actual document ID
        privilege="write",
    )
    db.commit()
    print("Granted write permission to admin group on document_123")

    print("\n=== Checking Permissions ===")

    # Check if user has permission
    has_read = rbac.has_permission(
        identity_key=user["object_id"],
        target_oid=document_item["object_id"],  # Use the actual document ID
        privilege="read",
    )
    print(f"User has read permission: {has_read}")

    has_write = rbac.has_permission(
        identity_key=user["object_id"],
        target_oid=document_item["object_id"],  # Use the actual document ID
        privilege="write",
    )
    print(f"User has write permission: {has_write}")

    print("\n=== Example completed successfully! ===")


if __name__ == "__main__":
    main()
