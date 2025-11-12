"""
Simple Authentication Microservice with RBAC (PostgreSQL with UUID + Redis Sessions)
- Each user has ONE role
- Roles can access multiple modules
- Full access to modules (no granular permissions)
- JWT Bearer Token authentication
- Redis-based session storage with PostgreSQL fallback
"""

import os
import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import logging

# Import database modules (PostgreSQL with UUID support)
from database_postgres import (
    get_user_manager,
    get_role_manager,
    get_module_manager,
    get_session_manager,
    get_audit_logger
)

# Import session factory for Redis support
from session_factory import get_session_store

# Import authentication dependencies
from auth_dependencies import (
    get_current_user_from_token,
    get_current_active_user,
    require_admin as require_admin_dependency
)

# Initialize FastAPI
app = FastAPI(
    title="Authentication Service with RBAC",
    version="3.0.0",
    description="Simple RBAC with module-level access control (PostgreSQL + UUID + Redis + JWT Bearer)",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json"
)

# Create API router with /api/v1 prefix
from fastapi import APIRouter
api_v1 = APIRouter(prefix="/api/v1")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv('CORS_ORIGINS', '*').split(','),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
class AuthConfig:
    SERVICE_NAME = os.getenv('SERVICE_NAME', 'auth-service')
    SERVICE_PORT = int(os.getenv('SERVICE_PORT', 8000))
    ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600))
    SESSION_STORE = os.getenv('SESSION_STORE', 'redis')  # redis, postgres, or hybrid
    JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION = int(os.getenv('JWT_EXPIRATION', 3600))

config = AuthConfig()
security = HTTPBearer()

# Get managers
user_manager = get_user_manager()
role_manager = get_role_manager()
module_manager = get_module_manager()
postgres_session_manager = get_session_manager()  # Keep for factory
audit_logger = get_audit_logger()

# Initialize session store (Redis, PostgreSQL, or Hybrid)
session_store = get_session_store(
    postgres_session_manager=postgres_session_manager,
    user_manager=user_manager
)

logger.info(f"Session store initialized: {config.SESSION_STORE}")

# ============================================================================
# DATA MODELS
# ============================================================================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    role_name: str = 'viewer'  # Role name instead of role_id for easier API usage
    phone: Optional[str] = None
    department: Optional[str] = None

class UserProfile(BaseModel):
    user_id: str
    email: str
    first_name: str
    last_name: str
    role_id: Optional[str]  # UUID as string
    role_name: Optional[str] = None
    department: Optional[str]
    status: str
    modules: List[Dict]

class SessionInfo(BaseModel):
    session_id: str
    user: UserProfile
    created_at: str
    expires_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class UpdateUserRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    department: Optional[str] = None
    role_name: Optional[str] = None  # Using role_name for easier API usage

class CreateRoleRequest(BaseModel):
    role_name: str
    description: Optional[str] = None
    is_active: bool = True

class UpdateRoleRequest(BaseModel):
    role_name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None

class CreateModuleRequest(BaseModel):
    module_code: str
    module_name: str
    description: Optional[str] = None
    icon: Optional[str] = None
    display_order: int = 0
    is_active: bool = True

class UpdateModuleRequest(BaseModel):
    module_code: Optional[str] = None
    module_name: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    display_order: Optional[int] = None
    is_active: Optional[bool] = None

class AssignModulesToRoleRequest(BaseModel):
    module_ids: List[str]  # List of module UUIDs
    has_access: bool = True

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_jwt_token(**user_data) -> str:
    """Create a JWT access token"""
  
    payload = {
        'user_id': user_data['user_id'],
        'email': user_data['email'],
        'role_id': user_data.get('role_id', ''),
        'role_name': user_data.get('role_name', ''),
        'modules': user_data.get('modules', []),
        'exp': datetime.utcnow() + timedelta(seconds=config.JWT_EXPIRATION),
        'iat': datetime.utcnow()
    }

    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_client_info(request: Request) -> tuple:
    """Extract client IP and user agent"""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get('user-agent', 'Unknown')
    return ip_address, user_agent

def get_role_id_by_name(role_name: str) -> Optional[str]:
    """Helper function to get role UUID by role name"""
    role = role_manager.get_role_by_name(role_name)
    return role['id'] if role else None

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

# @api_v1.post("/auth/signup")
# async def signup(request_data: SignupRequest, request: Request):
#     """Register a new user with a role"""
#     ip_address, user_agent = get_client_info(request)

#     # Get role_id from role_name
#     role_id = get_role_id_by_name(request_data.role_name)
#     if not role_id:
#         raise HTTPException(status_code=400, detail=f"Role '{request_data.role_name}' not found")

#     try:
#         user_id = user_manager.create_user(
#             email=request_data.email,
#             password=request_data.password,
#             first_name=request_data.first_name,
#             last_name=request_data.last_name,
#             role_id=role_id,
#             phone=request_data.phone,
#             department=request_data.department
#         )

#         audit_logger.log_event(
#             event_type='USER_SIGNUP',
#             event_description=f'New user registered: {request_data.email} with role: {request_data.role_name}',
#             user_id=user_id,
#             ip_address=ip_address,
#             user_agent=user_agent,
#             success=True
#         )

#         return {
#             "message": "User created successfully",
#             "user_id": user_id,
#             "email": request_data.email,
#             "role": request_data.role_name
#         }

#     except ValueError as e:
#         audit_logger.log_event(
#             event_type='USER_SIGNUP',
#             event_description=f'Failed signup: {request_data.email} - {str(e)}',
#             ip_address=ip_address,
#             user_agent=user_agent,
#             success=False
#         )
#         raise HTTPException(status_code=400, detail=str(e))

@api_v1.post("/auth/login", response_model=TokenResponse)
async def login(request_data: LoginRequest, request: Request):
    """
    Login with email and password
    Returns JWT bearer token for authentication
    """
    ip_address, user_agent = get_client_info(request)

    user = user_manager.authenticate_user(request_data.email, request_data.password)

    if not user:
        audit_logger.log_event(
            event_type='LOGIN_FAILED',
            event_description=f'Failed login: {request_data.email}',
            ip_address=ip_address,
            user_agent=user_agent,
            success=False
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Get user's modules
    modules = module_manager.get_user_modules(user['user_id'])
    module_codes = [m['module_code'] for m in modules]

    # Create session in Redis/PostgreSQL for tracking (optional - for audit/revocation)
    session_id = session_store.create_session(
        user_id=user['user_id'],
        email=user['email'],
        first_name=user['first_name'],
        last_name=user['last_name'],
        role_id=user.get('role_id'),
        department=user.get('department'),
        status=user['status'],
        session_timeout=config.SESSION_TIMEOUT,
        ip_address=ip_address,
        user_agent=user_agent
    )

    # Create JWT token
    access_token = create_jwt_token(
        user_id=user['user_id'],
        email=user['email'],
        role_id=user.get('role_id', ''),  # UUID as string
        modules=module_codes,
        role_name=user.get('role_name', '' )
    )

    audit_logger.log_event(
        event_type='LOGIN_SUCCESS',
        event_description=f'User logged in: {user["email"]}',
        user_id=user['user_id'],
        ip_address=ip_address,
        user_agent=user_agent,
        success=True
    )

    logger.info(f"User {user['email']} logged in successfully with session {session_id}")

    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=config.JWT_EXPIRATION
    )

@api_v1.post("/auth/logout")
async def logout(current_user: Dict = Depends(get_current_user_from_token)):
    """
    Logout user (invalidate all sessions)
    Requires valid JWT bearer token
    """
    user_id = current_user['user_id']
    email = current_user['email']

    # Delete all user sessions from store (for audit/revocation tracking)
    deleted_count = session_store.delete_user_sessions(user_id)

    audit_logger.log_event(
        event_type='LOGOUT',
        event_description=f'User logged out: {email} ({deleted_count} sessions deleted)',
        user_id=user_id,
        success=True
    )

    logger.info(f"User {email} logged out, {deleted_count} sessions deleted")

    return {
        "message": "Logged out successfully",
        "sessions_deleted": deleted_count
    }

# ============================================================================
# USER & SESSION ENDPOINTS
# ============================================================================

@api_v1.get("/auth/user", response_model=UserProfile)
async def get_current_user(current_user: Dict = Depends(get_current_user_from_token)):
    """
    Get current user profile from JWT token
    Requires valid JWT bearer token in Authorization header
    """
    user_id = current_user['user_id']

    # Get fresh user data from database
    user = user_manager.get_user_by_id(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get user's modules
    modules = module_manager.get_user_modules(user_id)

    # Get role name from role_id
    role_name = None
    if user.get('role_id'):
        roles = role_manager.get_all_roles()
        for role in roles:
            if role['id'] == user['role_id']:
                role_name = role['role_name']
                break

    return UserProfile(
        user_id=user['user_id'],
        email=user['email'],
        first_name=user['first_name'],
        last_name=user['last_name'],
        role_id=user.get('role_id'),
        role_name=role_name,
        department=user.get('department'),
        status=user['status'],
        modules=modules
    )

@api_v1.get("/auth/modules")
async def get_user_modules(current_user: Dict = Depends(get_current_user_from_token)):
    """
    Get modules accessible by current user from JWT token
    Requires valid JWT bearer token
    """
    # Modules are already in the JWT token
    return {
        "user_id": current_user['user_id'],
        "email": current_user['email'],
        "role_id": current_user.get('role_id'),
        "modules": current_user.get('modules', [])
    }

@api_v1.get("/auth/check-module/{module_code}")
async def check_module_access(module_code: str, current_user: Dict = Depends(get_current_user_from_token)):
    """
    Check if user can access a specific module
    Requires valid JWT bearer token
    """
    modules = current_user.get('modules', [])
    has_access = module_code in modules or module_code.upper() in modules

    return {
        "user": current_user['email'],
        "user_id": current_user['user_id'],
        "role_id": current_user.get('role_id'),
        "module_code": module_code,
        "has_access": has_access
    }

# ============================================================================
# ADMIN ENDPOINTS
# ============================================================================

@api_v1.get("/admin/users")
async def list_users(admin_user: Dict = Depends(require_admin_dependency)):
    """
    List all users (admin only)
    Requires valid JWT bearer token with admin access
    """
    users = user_manager.list_users()

    # Add role name and modules to each user
    for user in users:
        user['modules'] = module_manager.get_user_modules(user['user_id'])
        # Get role name
        if user.get('role_id'):
            roles = role_manager.get_all_roles()
            for role in roles:
                if role['id'] == user['role_id']:
                    user['role_name'] = role['role_name']
                    break

    return {"users": users, "count": len(users)}

@api_v1.post("/admin/users")
async def create_user(
    request_data: SignupRequest,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """Create a new user (admin only)"""
    # Get role_id from role_name
    role_id = get_role_id_by_name(request_data.role_name)
    if not role_id:
        raise HTTPException(status_code=400, detail=f"Role '{request_data.role_name}' not found")

    try:
        user_id = user_manager.create_user(
            email=request_data.email,
            password=request_data.password,
            first_name=request_data.first_name,
            last_name=request_data.last_name,
            role_id=role_id,
            phone=request_data.phone,
            department=request_data.department,
            created_by=admin_user['user_id']
        )

        audit_logger.log_event(
            event_type='USER_CREATED',
            event_description=f'Admin created user: {request_data.email} with role: {request_data.role_name}',
            user_id=admin_user['user_id'],
            success=True
        )

        return {
            "message": "User created successfully",
            "user_id": user_id
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_v1.put("/admin/users/{user_id}")
async def update_user(
    user_id: str,
    update_data: UpdateUserRequest,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """Update user (admin only)"""
    update_dict = update_data.dict(exclude_none=True)

    # Convert role_name to role_id if provided
    if 'role_name' in update_dict:
        role_name = update_dict.pop('role_name')
        role_id = get_role_id_by_name(role_name)
        if not role_id:
            raise HTTPException(status_code=400, detail=f"Role '{role_name}' not found")
        update_dict['role_id'] = role_id

    success = user_manager.update_user(user_id, **update_dict)

    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    audit_logger.log_event(
        event_type='USER_UPDATED',
        event_description=f'Admin updated user: {user_id}',
        user_id=admin_user['user_id'],
        success=True
    )

    return {"message": "User updated successfully"}

@api_v1.put("/admin/users/{user_id}/role/{role_name}")
async def assign_role(
    user_id: str,
    role_name: str,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """Assign role to user (admin only)"""
    role_id = get_role_id_by_name(role_name)
    if not role_id:
        raise HTTPException(status_code=400, detail=f"Role '{role_name}' not found")

    success = role_manager.assign_role(user_id, role_id)

    if not success:
        raise HTTPException(status_code=400, detail="Failed to assign role")

    audit_logger.log_event(
        event_type='ROLE_ASSIGNED',
        event_description=f'Admin assigned role {role_name} to user {user_id}',
        user_id=admin_user['user_id'],
        success=True
    )

    return {"message": f"Role '{role_name}' assigned successfully"}

@api_v1.get("/admin/roles")
async def list_roles(admin_user: Dict = Depends(require_admin_dependency)):
    """List all roles (admin only)"""
    roles = role_manager.get_all_roles()

    # Add module count to each role
    for role in roles:
        modules = module_manager.get_role_modules(role['id'])
        role['module_count'] = len(modules)
        role['modules'] = modules

    return {"roles": roles, "count": len(roles)}

@api_v1.get("/admin/modules")
async def list_modules(admin_user: Dict = Depends(require_admin_dependency)):
    """List all modules (admin only)"""
    modules = module_manager.get_all_modules()
    return {"modules": modules, "count": len(modules)}

@api_v1.post("/admin/roles")
async def create_role(
    request_data: CreateRoleRequest,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """
    Create a new role (admin only)
    """
    try:
        role_id = role_manager.create_role(
            role_name=request_data.role_name,
            description=request_data.description,
            is_active=request_data.is_active
        )

        audit_logger.log_event(
            event_type='ROLE_CREATED',
            event_description=f'Admin created role: {request_data.role_name}',
            user_id=admin_user['user_id'],
            success=True
        )

        return {
            "message": "Role created successfully",
            "role_id": role_id,
            "role_name": request_data.role_name
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_v1.put("/admin/roles/{role_id}")
async def update_role(
    role_id: str,
    request_data: UpdateRoleRequest,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """
    Update role details (admin only)
    """
    try:
        success = role_manager.update_role(
            role_id=role_id,
            role_name=request_data.role_name,
            description=request_data.description,
            is_active=request_data.is_active
        )

        if not success:
            raise HTTPException(status_code=404, detail="Role not found or no changes made")

        audit_logger.log_event(
            event_type='ROLE_UPDATED',
            event_description=f'Admin updated role: {role_id}',
            user_id=admin_user['user_id'],
            success=True
        )

        return {"message": "Role updated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_v1.delete("/admin/roles/{role_id}")
async def delete_role(
    role_id: str,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """
    Delete role (soft delete - sets is_active to false) (admin only)
    """
    success = role_manager.delete_role(role_id)

    if not success:
        raise HTTPException(status_code=404, detail="Role not found")

    audit_logger.log_event(
        event_type='ROLE_DELETED',
        event_description=f'Admin deleted role: {role_id}',
        user_id=admin_user['user_id'],
        success=True
    )

    return {"message": "Role deleted successfully"}

@api_v1.post("/admin/modules")
async def create_module(
    request_data: CreateModuleRequest,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """
    Create a new module (admin only)
    """
    try:
        module_id = module_manager.create_module(
            module_code=request_data.module_code,
            module_name=request_data.module_name,
            description=request_data.description,
            icon=request_data.icon,
            display_order=request_data.display_order,
            is_active=request_data.is_active
        )

        audit_logger.log_event(
            event_type='MODULE_CREATED',
            event_description=f'Admin created module: {request_data.module_code}',
            user_id=admin_user['user_id'],
            module_code=request_data.module_code,
            success=True
        )

        return {
            "message": "Module created successfully",
            "module_id": module_id,
            "module_code": request_data.module_code
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_v1.put("/admin/modules/{module_id}")
async def update_module(
    module_id: str,
    request_data: UpdateModuleRequest,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """
    Update module details (admin only)
    """
    try:
        success = module_manager.update_module(
            module_id=module_id,
            module_code=request_data.module_code,
            module_name=request_data.module_name,
            description=request_data.description,
            icon=request_data.icon,
            display_order=request_data.display_order,
            is_active=request_data.is_active
        )

        if not success:
            raise HTTPException(status_code=404, detail="Module not found or no changes made")

        audit_logger.log_event(
            event_type='MODULE_UPDATED',
            event_description=f'Admin updated module: {module_id}',
            user_id=admin_user['user_id'],
            success=True
        )

        return {"message": "Module updated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_v1.delete("/admin/modules/{module_id}")
async def delete_module(
    module_id: str,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """
    Delete module (soft delete - sets is_active to false) (admin only)
    """
    success = module_manager.delete_module(module_id)

    if not success:
        raise HTTPException(status_code=404, detail="Module not found")

    audit_logger.log_event(
        event_type='MODULE_DELETED',
        event_description=f'Admin deleted module: {module_id}',
        user_id=admin_user['user_id'],
        success=True
    )

    return {"message": "Module deleted successfully"}

@api_v1.post("/admin/roles/{role_id}/modules")
async def assign_modules_to_role(
    role_id: str,
    request_data: AssignModulesToRoleRequest,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """
    Assign multiple modules to a role (admin only)
    This will grant or update access for the specified modules
    """
    # Verify role exists
    role = role_manager.get_role_by_name(role_id)
    if not role:
        # Try getting by UUID
        roles = role_manager.get_all_roles()
        role = next((r for r in roles if r['id'] == role_id), None)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

    # Verify all modules exist
    for module_id in request_data.module_ids:
        module = module_manager.get_module_by_id(module_id)
        if not module:
            raise HTTPException(status_code=404, detail=f"Module with ID {module_id} not found")

    success = role_manager.assign_modules_to_role(
        role_id=role_id,
        module_ids=request_data.module_ids,
        has_access=request_data.has_access
    )

    if not success:
        raise HTTPException(status_code=400, detail="Failed to assign modules to role")

    audit_logger.log_event(
        event_type='ROLE_MODULES_ASSIGNED',
        event_description=f'Admin assigned {len(request_data.module_ids)} modules to role {role_id}',
        user_id=admin_user['user_id'],
        success=True
    )

    return {
        "message": f"Successfully assigned {len(request_data.module_ids)} modules to role",
        "role_id": role_id,
        "modules_count": len(request_data.module_ids)
    }

@api_v1.delete("/admin/roles/{role_id}/modules/{module_id}")
async def remove_module_from_role(
    role_id: str,
    module_id: str,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """
    Remove a module from a role (admin only)
    """
    success = role_manager.remove_module_from_role(role_id, module_id)

    if not success:
        raise HTTPException(status_code=404, detail="Role-Module association not found")

    audit_logger.log_event(
        event_type='ROLE_MODULE_REMOVED',
        event_description=f'Admin removed module {module_id} from role {role_id}',
        user_id=admin_user['user_id'],
        success=True
    )

    return {"message": "Module removed from role successfully"}

@api_v1.get("/admin/audit-log")
async def get_audit_log(
    limit: int = 100,
    admin_user: Dict = Depends(require_admin_dependency)
):
    """Get audit log (admin only)"""
    events = audit_logger.get_recent_events(limit)
    return {"events": events, "count": len(events)}

# ============================================================================
# INFO ENDPOINTS
# ============================================================================

@api_v1.get("/auth/info")
async def auth_info():
    """Service information"""
    return {
        "service": "Authentication Service with RBAC (PostgreSQL + UUID)",
        "version": "2.0.0",
        "environment": config.ENVIRONMENT,
        "database": "PostgreSQL",
        "features": {
            "rbac": True,
            "module_access": True,
            "session_management": True,
            "jwt_tokens": True,
            "audit_logging": True,
            "uuid_support": True
        },
        "endpoints": {
            "login": "/api/v1/auth/login",
            "signup": "/api/v1/auth/signup",
            "logout": "/api/v1/auth/logout",
            "user": "/api/v1/auth/user",
            "modules": "/api/v1/auth/modules"
        }
    }

@api_v1.get("/auth/roles")
async def get_available_roles(admin_user: Dict = Depends(require_admin_dependency)):
    """Get list of available roles (admin only)"""
    roles = role_manager.get_all_roles()
    return {"roles": roles}

# ============================================================================
# Include API Router
# ============================================================================

# Include the versioned API router
app.include_router(api_v1)

# ============================================================================
# ROOT LEVEL ENDPOINTS (No versioning)
# ============================================================================

@app.get("/health")
async def root_health_check():
    """Root level health check endpoint with Redis status"""
    redis_healthy = False
    redis_info = "not configured"

    try:
        redis_healthy = session_store.health_check()
        redis_info = "connected" if redis_healthy else "disconnected"
    except Exception as e:
        redis_info = f"error: {str(e)}"

    overall_status = "healthy" if redis_healthy else "degraded"

    return {
        "status": overall_status,
        "service": config.SERVICE_NAME,
        "version": "3.0.0",
        "api_version": "v1",
        "timestamp": datetime.now().isoformat(),
        "environment": config.ENVIRONMENT,
        "components": {
            "database": "PostgreSQL",
            "session_store": config.SESSION_STORE,
            "redis": redis_info,
            "authentication": "JWT Bearer Token"
        }
    }

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Authentication Service with RBAC (PostgreSQL + UUID + Redis + JWT Bearer)",
        "version": "3.0.0",
        "api_version": "v1",
        "docs": "/api/v1/docs",
        "health": "/health",
        "authentication": "JWT Bearer Token (Authorization: Bearer <token>)",
        "session_store": config.SESSION_STORE,
        "endpoints": {
            "authentication": "/api/v1/auth",
            "admin": "/api/v1/admin"
        }
    }

# ============================================================================
# STARTUP/SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Run on startup"""
    logger.info(f"Starting {config.SERVICE_NAME} v3.0.0 (PostgreSQL + Redis + JWT Bearer)")
    logger.info(f"Environment: {config.ENVIRONMENT}")
    logger.info(f"Session store: {config.SESSION_STORE}")
    logger.info(f"Authentication: JWT Bearer Token")

    # Check Redis health
    try:
        if session_store.health_check():
            logger.info("✓ Session store healthy")
        else:
            logger.warning("✗ Session store unhealthy")
    except Exception as e:
        logger.error(f"✗ Session store check failed: {e}")

    # Cleanup expired sessions
    try:
        expired_count = session_store.cleanup_expired_sessions()
        logger.info(f"Cleaned up {expired_count} expired sessions")
    except Exception as e:
        logger.warning(f"Could not cleanup sessions: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Run on shutdown"""
    logger.info(f"Shutting down {config.SERVICE_NAME}")

    # Close Redis connection if applicable
    try:
        if hasattr(session_store, 'close'):
            session_store.close()
            logger.info("Session store connection closed")
    except Exception as e:
        logger.warning(f"Error closing session store: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=config.SERVICE_PORT,
        log_level="info"
    )
