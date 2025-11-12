"""
Authentication Dependencies
JWT Bearer Token validation and user extraction
"""

import logging
from typing import Dict, Optional
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import os

logger = logging.getLogger(__name__)

# Security scheme for bearer token
security = HTTPBearer()


class AuthConfig:
    """Authentication configuration"""
    JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
    JWT_ALGORITHM = 'HS256'


def verify_jwt_token(token: str) -> Dict:
    """
    Verify and decode JWT token

    Args:
        token: JWT token string

    Returns:
        Dict: Decoded token payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            AuthConfig.JWT_SECRET,
            algorithms=[AuthConfig.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )


def get_current_user_from_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict:
    """
    Extract and validate current user from JWT bearer token

    This is a FastAPI dependency that:
    1. Extracts the bearer token from Authorization header
    2. Validates the JWT token
    3. Returns the decoded user information

    Usage in endpoints:
        @app.get("/protected")
        async def protected_route(current_user: Dict = Depends(get_current_user_from_token)):
            return {"user": current_user}

    Args:
        credentials: HTTP bearer credentials from Authorization header

    Returns:
        Dict: User information from token payload containing:
            - user_id: User's unique identifier
            - email: User's email address
            - role_id: User's role identifier
            - modules: List of accessible module codes

    Raises:
        HTTPException: 401 if token is missing, invalid, or expired
    """
    token = credentials.credentials

    # Verify and decode the token
    payload = verify_jwt_token(token)

    # Extract user information
    user_info = {
        'user_id': payload.get('user_id'),
        'email': payload.get('email'),
        'role_id': payload.get('role_id'),
        'modules': payload.get('modules', []),
        'role_name': payload.get('role_name', '' )
    }

    # Validate required fields
    if not user_info['user_id'] or not user_info['email']:
        logger.error("Token missing required user information")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing user information",
            headers={"WWW-Authenticate": "Bearer"}
        )

    logger.debug(f"Authenticated user: {user_info['email']}")
    return user_info


def get_current_active_user(
    current_user: Dict = Depends(get_current_user_from_token)
) -> Dict:
    """
    Get current active user (can be extended with additional checks)

    This dependency can be used to add additional validation:
    - Check if user is active in database
    - Check if user has been banned
    - Check if user's role has been changed
    - etc.

    For now, it just passes through the token user info.

    Args:
        current_user: User info from JWT token

    Returns:
        Dict: User information

    Raises:
        HTTPException: 403 if user is not active
    """
    # In the future, you could add database checks here:
    # - Verify user still exists and is active
    # - Check for user bans or suspensions
    # - Validate role hasn't changed

    return current_user


def require_admin(current_user: Dict = Depends(get_current_user_from_token)) -> Dict:
    """
    Dependency to require admin role

    Usage:
        @app.get("/admin/users")
        async def list_users(admin_user: Dict = Depends(require_admin)):
            return {"users": [...]}

    Args:
        current_user: User info from JWT token

    Returns:
        Dict: Admin user information

    Raises:
        HTTPException: 403 if user is not an admin
    """
    # Check if user has admin access
    # This could be enhanced to check modules or specific role_id
    modules = current_user.get('modules', [])
    role_name = current_user.get('role_name', '')
    # For now, check if user has access to admin module
    if role_name not in ['admin','ADMIN']:
        logger.warning(f"User {current_user['email']} attempted to access admin endpoint")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    return current_user


def require_module_access(module_code: str):
    """
    Dependency factory to require access to specific module

    Usage:
        @app.get("/analytics/report")
        async def get_report(
            user: Dict = Depends(require_module_access("ANALYTICS"))
        ):
            return {"report": [...]}

    Args:
        module_code: Module code to check access for

    Returns:
        Dependency function that checks module access

    Raises:
        HTTPException: 403 if user doesn't have access to module
    """
    def check_module_access(current_user: Dict = Depends(get_current_user_from_token)) -> Dict:
        modules = current_user.get('modules', [])

        if module_code not in modules and module_code.upper() not in modules:
            logger.warning(
                f"User {current_user['email']} attempted to access "
                f"module '{module_code}' without permission"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: {module_code} module required"
            )

        return current_user

    return check_module_access


# Optional: Get user from token without raising exception
def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
) -> Optional[Dict]:
    """
    Get user from token if present, otherwise return None

    Useful for endpoints that have different behavior for authenticated vs anonymous users

    Args:
        credentials: Optional bearer credentials

    Returns:
        Dict: User info if authenticated, None otherwise
    """
    if not credentials:
        return None

    try:
        token = credentials.credentials
        payload = verify_jwt_token(token)

        return {
            'user_id': payload.get('user_id'),
            'email': payload.get('email'),
            'role_id': payload.get('role_id'),
            'modules': payload.get('modules', [])
        }
    except HTTPException:
        return None
