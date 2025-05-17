#!/usr/bin/env python3
"""
Database migration script for the Azure Drift Detector application.
"""

import os
import sys
from flask_migrate import Migrate, current, stamp, init as flask_init
from flask_migrate import migrate as flask_migrate, upgrade as flask_upgrade
from app import app, db

def create_migration_directory():
    """Initialize the migration repository if it doesn't exist"""
    print("Initializing migration repository...")
    if not os.path.exists('migrations'):
        with app.app_context():
            flask_init()
        print("Migration repository initialized.")
    else:
        print("Migration repository already exists.")

def create_migration(message=None):
    """Create a migration based on the current models"""
    message = message or "Auto-generated migration"
    print(f"Creating migration: {message}")
    with app.app_context():
        flask_migrate(message=message)
    print("Migration created successfully.")

def upgrade_database():
    """Apply all pending migrations to the database"""
    print("Upgrading database...")
    with app.app_context():
        flask_upgrade()
    print("Database upgraded successfully.")

def stamp_database():
    """Mark the current database version without running migrations"""
    print("Stamping database with current migration...")
    with app.app_context():
        current_rev = current()
        if current_rev:
            stamp(current_rev)
            print(f"Database stamped with revision: {current_rev}")
        else:
            print("No revision found. Make sure you've created a migration first.")

def run_full_migration(message=None):
    """Run the complete migration process"""
    create_migration_directory()
    create_migration(message)
    upgrade_database()
    print("\nMigration process completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "init":
            create_migration_directory()
        elif command == "migrate":
            message = sys.argv[2] if len(sys.argv) > 2 else None
            create_migration(message)
        elif command == "upgrade":
            upgrade_database()
        elif command == "stamp":
            stamp_database()
        elif command == "full":
            message = sys.argv[2] if len(sys.argv) > 2 else None
            run_full_migration(message)
        else:
            print("Unknown command. Use 'init', 'migrate', 'upgrade', 'stamp', or 'full'.")
    else:
        print("Usage: python migrations.py [init|migrate|upgrade|stamp|full] [migration_message]")
        print("  init - Initialize the migration repository")
        print("  migrate - Create a new migration based on model changes")
        print("  upgrade - Apply pending migrations to the database")
        print("  stamp - Mark the current database version without running migrations")
        print("  full - Run the complete migration process (init, migrate, upgrade)")
        print("  migration_message - Optional description for the migration (used with migrate and full)")