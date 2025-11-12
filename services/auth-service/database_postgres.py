"""
PostgreSQL Database module for authentication service with RBAC
Handles users, roles, modules, and simple access control with UUID support
"""

import psycopg2
import psycopg2.extras
import secrets
import bcrypt
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict
import logging
import os

logger = logging.getLogger(__name__)

# Database configuration from environment variables
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'auth_service'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}


class DatabaseManager:
    """Manages database connections and operations"""

    def __init__(self, db_config: dict = DB_CONFIG):
        self.db_config = db_config
        self.init_database()

    def get_connection(self):
        """Get a database connection"""
        conn = psycopg2.connect(**self.db_config)
        return conn

    def init_database(self):
        """Initialize database with schema"""
        schema_path = os.path.join(os.path.dirname(__file__), 'schema_postgres.sql')

        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                schema_sql = f.read()

            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(schema_sql)
                conn.commit()
                logger.info("Database initialized successfully")
            except Exception as e:
                logger.error(f"Error initializing database: {str(e)}")
                conn.rollback()
                raise
            finally:
                cursor.close()
                conn.close()
        else:
            logger.warning(f"Schema file not found at {schema_path}")

    def execute_query(self, query: str, params: tuple = ()) -> List[Dict]:
        """Execute a SELECT query and return results as list of dicts"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(query, params)
            results = cursor.fetchall()
            return [dict(row) for row in results]
        finally:
            cursor.close()
            conn.close()

    def execute_update(self, query: str, params: tuple = ()) -> int:
        """Execute an INSERT/UPDATE/DELETE query and return affected rows"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount
        finally:
            cursor.close()
            conn.close()

    def execute_insert(self, query: str, params: tuple = ()) -> str:
        """Execute an INSERT query and return the UUID of inserted row"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query + " RETURNING id", params)
            result = cursor.fetchone()
            conn.commit()
            return str(result[0]) if result else None
        finally:
            cursor.close()
            conn.close()


class UserManager:
    """Manages user-related database operations"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

    def create_user(self, email: str, password: str, first_name: str, last_name: str, role_id: str,
                   phone: Optional[str] = None, department: Optional[str] = None,
                   created_by: Optional[str] = None) -> str:
        """Create a new user with ONE role and return user_id"""
        user_id = f"user-{secrets.token_hex(8)}"
        password_hash = self.hash_password(password)

        query = """
            INSERT INTO users (user_id, email, password_hash, first_name, last_name, phone, department, role_id, status, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active', %s)
        """

        try:
            self.db.execute_insert(query, (user_id, email, password_hash, first_name, last_name, phone, department, role_id, created_by))
            logger.info(f"User created: {email} with role_id: {role_id}")
            return user_id
        except psycopg2.IntegrityError:
            logger.error(f"User already exists: {email}")
            raise ValueError("User with this email already exists")

    def authenticate_user(self, email: str, password: str) -> Optional[Dict]:
        """Authenticate user and return user info if successful"""
        # query = "SELECT * FROM users WHERE email = %s AND status = 'active'"
        
        query=  ''' 
                SELECT u.*, r.role_name AS role_name
                FROM users u
                JOIN roles r ON r.id = u.role_id
                WHERE u.email = %s AND u.status = 'active' AND r.is_active = true;
            '''
        results = self.db.execute_query(query, (email,))
        
        if not results:
            return None

        user = results[0]

        if self.verify_password(password, user['password_hash']):
            # Update last login
            self.db.execute_update(
                "UPDATE users SET last_login = %s WHERE user_id = %s",
                (datetime.now(), user['user_id'])
            )
            # Convert UUID to string for JSON serialization
            if user.get('role_id'):
                user['role_id'] = str(user['role_id'])
            if user.get('id'):
                user['id'] = str(user['id'])
            return user

        return None

    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user by user_id"""
        query = "SELECT * FROM users WHERE user_id = %s"
        results = self.db.execute_query(query, (user_id,))
        if results:
            user = results[0]
            # Convert UUIDs to strings
            if user.get('role_id'):
                user['role_id'] = str(user['role_id'])
            if user.get('id'):
                user['id'] = str(user['id'])
            return user
        return None

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        query = "SELECT * FROM users WHERE email = %s"
        results = self.db.execute_query(query, (email,))
        if results:
            user = results[0]
            # Convert UUIDs to strings
            if user.get('role_id'):
                user['role_id'] = str(user['role_id'])
            if user.get('id'):
                user['id'] = str(user['id'])
            return user
        return None

    def list_users(self, status: str = 'active') -> List[Dict]:
        """List all users"""
        query = "SELECT * FROM users WHERE status = %s ORDER BY first_name, last_name"
        results = self.db.execute_query(query, (status,))
        # Convert UUIDs to strings
        for user in results:
            if user.get('role_id'):
                user['role_id'] = str(user['role_id'])
            if user.get('id'):
                user['id'] = str(user['id'])
        return results

    def update_user(self, user_id: str, **kwargs) -> bool:
        """Update user fields (including role)"""
        allowed_fields = ['first_name', 'last_name', 'phone', 'department', 'status', 'role_id']
        update_fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not update_fields:
            return False

        update_fields['updated_at'] = datetime.now()

        set_clause = ', '.join([f"{k} = %s" for k in update_fields.keys()])
        query = f"UPDATE users SET {set_clause} WHERE user_id = %s"

        params = list(update_fields.values()) + [user_id]
        affected = self.db.execute_update(query, tuple(params))

        return affected > 0

    def delete_user(self, user_id: str) -> bool:
        """Delete a user (soft delete by setting status to 'deleted')"""
        return self.update_user(user_id, status='deleted')


class RoleManager:
    """Manages role-related database operations"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def get_all_roles(self) -> List[Dict]:
        """Get all active roles"""
        query = "SELECT * FROM roles WHERE is_active = true ORDER BY role_name"
        results = self.db.execute_query(query)
        # Convert UUIDs to strings
        for role in results:
            if role.get('id'):
                role['id'] = str(role['id'])
        return results

    def get_role_by_name(self, role_name: str) -> Optional[Dict]:
        """Get role by name and return with UUID as string"""
        query = "SELECT * FROM roles WHERE role_name = %s"
        results = self.db.execute_query(query, (role_name,))
        if results:
            role = results[0]
            if role.get('id'):
                role['id'] = str(role['id'])
            return role
        return None

    def assign_role(self, user_id: str, role_id: str) -> bool:
        """Assign a role to a user (updates the user's role)"""
        query = "UPDATE users SET role_id = %s, updated_at = %s WHERE user_id = %s"
        try:
            affected = self.db.execute_update(query, (role_id, datetime.now(), user_id))
            if affected > 0:
                logger.info(f"Role ID '{role_id}' assigned to user {user_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error assigning role: {str(e)}")
            return False

    def get_user_role(self, user_id: str) -> Optional[str]:
        """Get the role_id for a user"""
        query = "SELECT role_id FROM users WHERE user_id = %s"
        results = self.db.execute_query(query, (user_id,))
        if results and results[0]['role_id']:
            return str(results[0]['role_id'])
        return None

    def get_users_by_role(self, role_id: str) -> List[Dict]:
        """Get all users with a specific role"""
        query = """
            SELECT * FROM users
            WHERE role_id = %s AND status = 'active'
            ORDER BY first_name, last_name
        """
        results = self.db.execute_query(query, (role_id,))
        # Convert UUIDs to strings
        for user in results:
            if user.get('role_id'):
                user['role_id'] = str(user['role_id'])
            if user.get('id'):
                user['id'] = str(user['id'])
        return results

    def create_role(self, role_name: str, description: Optional[str] = None, is_active: bool = True) -> str:
        """Create a new role and return role_id (UUID)"""
        query = """
            INSERT INTO roles (role_name, description, is_active)
            VALUES (%s, %s, %s)
        """
        try:
            role_id = self.db.execute_insert(query, (role_name, description, is_active))
            logger.info(f"Role created: {role_name} with ID: {role_id}")
            return role_id
        except psycopg2.IntegrityError:
            logger.error(f"Role already exists: {role_name}")
            raise ValueError("Role with this name already exists")

    def update_role(self, role_id: str, role_name: Optional[str] = None,
                    description: Optional[str] = None, is_active: Optional[bool] = None) -> bool:
        """Update role details"""
        update_fields = {}
        if role_name is not None:
            update_fields['role_name'] = role_name
        if description is not None:
            update_fields['description'] = description
        if is_active is not None:
            update_fields['is_active'] = is_active

        if not update_fields:
            return False

        set_clause = ', '.join([f"{k} = %s" for k in update_fields.keys()])
        query = f"UPDATE roles SET {set_clause} WHERE id = %s"
        params = list(update_fields.values()) + [role_id]

        try:
            affected = self.db.execute_update(query, tuple(params))
            return affected > 0
        except psycopg2.IntegrityError:
            logger.error(f"Role name already exists: {role_name}")
            raise ValueError("Role with this name already exists")

    def delete_role(self, role_id: str) -> bool:
        """Delete a role (soft delete by setting is_active to false)"""
        return self.update_role(role_id, is_active=False)

    def assign_modules_to_role(self, role_id: str, module_ids: List[str], has_access: bool = True) -> bool:
        """Assign multiple modules to a role"""
        query = """
            INSERT INTO role_module_access (role_id, module_id, has_access)
            VALUES (%s, %s, %s)
            ON CONFLICT (role_id, module_id) DO UPDATE SET has_access = EXCLUDED.has_access
        """
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            for module_id in module_ids:
                cursor.execute(query, (role_id, module_id, has_access))
            conn.commit()
            logger.info(f"Assigned {len(module_ids)} modules to role {role_id}")
            return True
        except Exception as e:
            logger.error(f"Error assigning modules to role: {str(e)}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            conn.close()

    def remove_module_from_role(self, role_id: str, module_id: str) -> bool:
        """Remove a module from a role"""
        query = "DELETE FROM role_module_access WHERE role_id = %s AND module_id = %s"
        try:
            affected = self.db.execute_update(query, (role_id, module_id))
            return affected > 0
        except Exception as e:
            logger.error(f"Error removing module from role: {str(e)}")
            return False


class ModuleManager:
    """Manages module access and permissions"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def get_all_modules(self) -> List[Dict]:
        """Get all active modules"""
        query = "SELECT * FROM modules WHERE is_active = true ORDER BY display_order, module_name"
        results = self.db.execute_query(query)
        # Convert UUIDs to strings
        for module in results:
            if module.get('id'):
                module['id'] = str(module['id'])
        return results

    def get_user_modules(self, user_id: str) -> List[Dict]:
        """Get all modules accessible by a user based on their role"""
        query = """
            SELECT
                m.id as module_id,
                m.module_code,
                m.module_name,
                m.description,
                m.icon,
                m.display_order
            FROM modules m
            JOIN role_module_access rma ON m.id = rma.module_id
            JOIN users u ON rma.role_id = u.role_id
            WHERE u.user_id = %s AND m.is_active = true AND rma.has_access = true
            ORDER BY m.display_order, m.module_name
        """
        results = self.db.execute_query(query, (user_id,))
        # Convert UUIDs to strings
        for module in results:
            if module.get('module_id'):
                module['module_id'] = str(module['module_id'])
        return results

    def can_access_module(self, user_id: str, module_code: str) -> bool:
        """Check if user can access a specific module (if yes, full access)"""
        query = """
            SELECT rma.has_access
            FROM role_module_access rma
            JOIN users u ON rma.role_id = u.role_id
            JOIN modules m ON rma.module_id = m.id
            WHERE u.user_id = %s AND m.module_code = %s
        """
        results = self.db.execute_query(query, (user_id, module_code))
        return bool(results and results[0]['has_access'])

    def get_role_modules(self, role_id: str) -> List[Dict]:
        """Get all modules accessible by a specific role"""
        query = """
            SELECT m.*, rma.has_access
            FROM modules m
            JOIN role_module_access rma ON m.id = rma.module_id
            WHERE rma.role_id = %s AND m.is_active = true AND rma.has_access = true
            ORDER BY m.display_order, m.module_name
        """
        results = self.db.execute_query(query, (role_id,))
        # Convert UUIDs to strings
        for module in results:
            if module.get('id'):
                module['id'] = str(module['id'])
        return results

    def create_module(self, module_code: str, module_name: str, description: Optional[str] = None,
                     icon: Optional[str] = None, display_order: int = 0, is_active: bool = True) -> str:
        """Create a new module and return module_id (UUID)"""
        query = """
            INSERT INTO modules (module_code, module_name, description, icon, display_order, is_active)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        try:
            module_id = self.db.execute_insert(query, (module_code, module_name, description, icon, display_order, is_active))
            logger.info(f"Module created: {module_code} with ID: {module_id}")
            return module_id
        except psycopg2.IntegrityError:
            logger.error(f"Module already exists: {module_code}")
            raise ValueError("Module with this code already exists")

    def get_module_by_code(self, module_code: str) -> Optional[Dict]:
        """Get module by module_code"""
        query = "SELECT * FROM modules WHERE module_code = %s"
        results = self.db.execute_query(query, (module_code,))
        if results:
            module = results[0]
            if module.get('id'):
                module['id'] = str(module['id'])
            return module
        return None

    def get_module_by_id(self, module_id: str) -> Optional[Dict]:
        """Get module by UUID"""
        query = "SELECT * FROM modules WHERE id = %s"
        results = self.db.execute_query(query, (module_id,))
        if results:
            module = results[0]
            if module.get('id'):
                module['id'] = str(module['id'])
            return module
        return None

    def update_module(self, module_id: str, module_code: Optional[str] = None,
                     module_name: Optional[str] = None, description: Optional[str] = None,
                     icon: Optional[str] = None, display_order: Optional[int] = None,
                     is_active: Optional[bool] = None) -> bool:
        """Update module details"""
        update_fields = {}
        if module_code is not None:
            update_fields['module_code'] = module_code
        if module_name is not None:
            update_fields['module_name'] = module_name
        if description is not None:
            update_fields['description'] = description
        if icon is not None:
            update_fields['icon'] = icon
        if display_order is not None:
            update_fields['display_order'] = display_order
        if is_active is not None:
            update_fields['is_active'] = is_active

        if not update_fields:
            return False

        set_clause = ', '.join([f"{k} = %s" for k in update_fields.keys()])
        query = f"UPDATE modules SET {set_clause} WHERE id = %s"
        params = list(update_fields.values()) + [module_id]

        try:
            affected = self.db.execute_update(query, tuple(params))
            return affected > 0
        except psycopg2.IntegrityError:
            logger.error(f"Module code already exists: {module_code}")
            raise ValueError("Module with this code already exists")

    def delete_module(self, module_id: str) -> bool:
        """Delete a module (soft delete by setting is_active to false)"""
        return self.update_module(module_id, is_active=False)


class SessionManager:
    """Manages session-related database operations"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def create_session(
        self,
        user_id: str,
        session_timeout: int = 3600,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """Create a new session and return session_id"""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(seconds=session_timeout)

        query = """
            INSERT INTO sessions (session_id, user_id, expires_at, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s)
        """

        self.db.execute_insert(query, (session_id, user_id, expires_at, ip_address, user_agent))
        logger.info(f"Session created for user {user_id}")

        return session_id

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by session_id"""
        query = """
            SELECT s.*, u.email, u.first_name, u.last_name, u.status, u.department, u.role_id
            FROM sessions s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.session_id = %s AND s.expires_at > %s AND u.status = 'active'
        """

        results = self.db.execute_query(query, (session_id, datetime.now()))

        if results:
            session = results[0]
            # Update last activity
            self.update_session_activity(session_id)
            # Convert UUIDs to strings
            if session.get('role_id'):
                session['role_id'] = str(session['role_id'])
            if session.get('id'):
                session['id'] = str(session['id'])
            return session

        return None

    def update_session_activity(self, session_id: str):
        """Update session last activity timestamp"""
        query = "UPDATE sessions SET last_activity = %s WHERE session_id = %s"
        self.db.execute_update(query, (datetime.now(), session_id))

    def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        query = "DELETE FROM sessions WHERE session_id = %s"
        affected = self.db.execute_update(query, (session_id,))
        return affected > 0

    def delete_user_sessions(self, user_id: str) -> int:
        """Delete all sessions for a user"""
        query = "DELETE FROM sessions WHERE user_id = %s"
        return self.db.execute_update(query, (user_id,))

    def cleanup_expired_sessions(self) -> int:
        """Delete all expired sessions"""
        query = "DELETE FROM sessions WHERE expires_at < %s"
        return self.db.execute_update(query, (datetime.now(),))

    def extend_session(self, session_id: str, additional_seconds: int = 3600) -> bool:
        """Extend session expiration"""
        query = "UPDATE sessions SET expires_at = %s WHERE session_id = %s"
        new_expiry = datetime.now() + timedelta(seconds=additional_seconds)
        affected = self.db.execute_update(query, (new_expiry, session_id))
        return affected > 0


class AuditLogger:
    """Manages audit log entries"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def log_event(
        self,
        event_type: str,
        event_description: str,
        user_id: Optional[str] = None,
        module_code: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True
    ):
        """Log an authentication or access event"""
        query = """
            INSERT INTO audit_log (user_id, event_type, event_description, module_code, ip_address, user_agent, success)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        self.db.execute_insert(
            query,
            (user_id, event_type, event_description, module_code, ip_address, user_agent, success)
        )

    def get_user_audit_log(self, user_id: str, limit: int = 100) -> List[Dict]:
        """Get audit log entries for a specific user"""
        query = """
            SELECT * FROM audit_log
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s
        """
        results = self.db.execute_query(query, (user_id, limit))
        # Convert UUIDs to strings
        for log in results:
            if log.get('id'):
                log['id'] = str(log['id'])
        return results

    def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent audit log entries"""
        query = "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT %s"
        results = self.db.execute_query(query, (limit,))
        # Convert UUIDs to strings
        for log in results:
            if log.get('id'):
                log['id'] = str(log['id'])
        return results

    def get_module_audit_log(self, module_code: str, limit: int = 100) -> List[Dict]:
        """Get audit log entries for a specific module"""
        query = """
            SELECT * FROM audit_log
            WHERE module_code = %s
            ORDER BY created_at DESC
            LIMIT %s
        """
        results = self.db.execute_query(query, (module_code, limit))
        # Convert UUIDs to strings
        for log in results:
            if log.get('id'):
                log['id'] = str(log['id'])
        return results


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_db_manager() -> DatabaseManager:
    """Get database manager instance (singleton pattern)"""
    if not hasattr(get_db_manager, '_instance'):
        get_db_manager._instance = DatabaseManager()
    return get_db_manager._instance


def get_user_manager() -> UserManager:
    """Get user manager instance"""
    return UserManager(get_db_manager())


def get_role_manager() -> RoleManager:
    """Get role manager instance"""
    return RoleManager(get_db_manager())


def get_module_manager() -> ModuleManager:
    """Get module manager instance"""
    return ModuleManager(get_db_manager())


def get_session_manager() -> SessionManager:
    """Get session manager instance"""
    return SessionManager(get_db_manager())


def get_audit_logger() -> AuditLogger:
    """Get audit logger instance"""
    return AuditLogger(get_db_manager())
