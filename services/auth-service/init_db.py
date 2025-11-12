"""
Database initialization script for Simple RBAC system
Run this script to initialize the database with schema and sample data
"""

import os
import sys
from database_simple import DatabaseManager, UserManager, RoleManager, ModuleManager
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_database():
    """Initialize the database"""
    logger.info("=" * 70)
    logger.info("Initializing Simple RBAC Database...")
    logger.info("=" * 70)

    # Create database manager
    db_manager = DatabaseManager()
    user_manager = UserManager(db_manager)
    role_manager = RoleManager(db_manager)
    module_manager = ModuleManager(db_manager)

    logger.info("\n✓ Database schema created successfully")

    # Display roles
    logger.info("\n" + "=" * 70)
    logger.info("Available Roles:")
    logger.info("=" * 70)
    roles = role_manager.get_all_roles()
    for role in roles:
        modules = module_manager.get_role_modules(role['role_name'])
        module_names = [m['module_name'] for m in modules]
        logger.info(f"  • {role['role_name']:<20} - {role['description']}")
        logger.info(f"    Modules: {', '.join(module_names)}")

    # Display modules
    logger.info("\n" + "=" * 70)
    logger.info("Available Modules:")
    logger.info("=" * 70)
    modules = module_manager.get_all_modules()
    for module in modules:
        logger.info(f"  • {module['module_name']:<30} [{module['module_code']}]")

    # Display sample users
    logger.info("\n" + "=" * 70)
    logger.info("Sample Users (password for all: password123):")
    logger.info("=" * 70)
    logger.info("  Email                      | Role             | Access")
    logger.info("  " + "-" * 66)
    logger.info("  admin@example.com          | admin            | All modules")
    logger.info("  contract@example.com       | contract_analyst | Contract Intelligence only")
    logger.info("  spend@example.com          | spend_analyst    | Spend Intelligence only")
    logger.info("  material@example.com       | material_analyst | Material Intelligence only")
    logger.info("  manager@example.com        | manager          | All modules")
    logger.info("  viewer@example.com         | viewer           | All modules")

    logger.info("\n" + "=" * 70)
    logger.info("Database initialization complete!")
    logger.info("=" * 70)
    logger.info("\n✓ You can now start the application:")
    logger.info("  python app_rbac.py")
    logger.info("\n✓ Or run with uvicorn:")
    logger.info("  uvicorn app_rbac:app --reload --host 0.0.0.0 --port 8000")
    logger.info("\n✓ API Documentation will be available at:")
    logger.info("  http://localhost:8000/docs")
    logger.info("")

if __name__ == "__main__":
    init_database()
