"""
Session Store Factory
Provides abstraction for session storage backend selection
"""

import os
import logging
from typing import Protocol, Optional, Dict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class SessionStoreProtocol(Protocol):
    """Protocol for session store implementations"""

    def create_session(
        self,
        user_id: str,
        email: str,
        first_name: str,
        last_name: str,
        role_id: Optional[str],
        department: Optional[str],
        status: str,
        session_timeout: int = 3600,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """Create a new session"""
        ...

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session data"""
        ...

    def update_session_activity(self, session_id: str) -> bool:
        """Update session last activity"""
        ...

    def extend_session(self, session_id: str, additional_seconds: int = 3600) -> bool:
        """Extend session expiration"""
        ...

    def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        ...

    def delete_user_sessions(self, user_id: str) -> int:
        """Delete all sessions for a user"""
        ...

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        ...

    def health_check(self) -> bool:
        """Check if session store is healthy"""
        ...


class PostgresSessionStoreAdapter:
    """
    Adapter for PostgreSQL SessionManager to match SessionStoreProtocol
    """

    def __init__(self, postgres_session_manager, user_manager):
        self.session_manager = postgres_session_manager
        self.user_manager = user_manager
        logger.info("Using PostgreSQL session store")

    def create_session(
        self,
        user_id: str,
        email: str,
        first_name: str,
        last_name: str,
        role_id: Optional[str],
        department: Optional[str],
        status: str,
        session_timeout: int = 3600,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """Create session in PostgreSQL"""
        # PostgreSQL SessionManager only needs user_id, not full user data
        return self.session_manager.create_session(
            user_id=user_id,
            session_timeout=session_timeout,
            ip_address=ip_address,
            user_agent=user_agent
        )

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session from PostgreSQL (includes user data via JOIN)"""
        return self.session_manager.get_session(session_id)

    def update_session_activity(self, session_id: str) -> bool:
        """Update session activity in PostgreSQL"""
        self.session_manager.update_session_activity(session_id)
        return True

    def extend_session(self, session_id: str, additional_seconds: int = 3600) -> bool:
        """Extend session in PostgreSQL"""
        return self.session_manager.extend_session(session_id, additional_seconds)

    def delete_session(self, session_id: str) -> bool:
        """Delete session from PostgreSQL"""
        return self.session_manager.delete_session(session_id)

    def delete_user_sessions(self, user_id: str) -> int:
        """Delete all user sessions from PostgreSQL"""
        return self.session_manager.delete_user_sessions(user_id)

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions in PostgreSQL"""
        return self.session_manager.cleanup_expired_sessions()

    def health_check(self) -> bool:
        """Check PostgreSQL health"""
        try:
            # Try to execute a simple query
            self.session_manager.cleanup_expired_sessions()
            return True
        except Exception as e:
            logger.error(f"PostgreSQL health check failed: {e}")
            return False


class HybridSessionStore:
    """
    Hybrid session store that uses Redis for active sessions
    and PostgreSQL for audit/persistence
    """

    def __init__(self, redis_store, postgres_adapter):
        self.redis = redis_store
        self.postgres = postgres_adapter
        logger.info("Using Hybrid session store (Redis + PostgreSQL)")

    def create_session(
        self,
        user_id: str,
        email: str,
        first_name: str,
        last_name: str,
        role_id: Optional[str],
        department: Optional[str],
        status: str,
        session_timeout: int = 3600,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """Create session in both Redis and PostgreSQL"""
        # Create in Redis (fast, for active sessions)
        session_id = self.redis.create_session(
            user_id=user_id,
            email=email,
            first_name=first_name,
            last_name=last_name,
            role_id=role_id,
            department=department,
            status=status,
            session_timeout=session_timeout,
            ip_address=ip_address,
            user_agent=user_agent
        )

        # Also create in PostgreSQL (audit trail)
        try:
            self.postgres.create_session(
                user_id=user_id,
                email=email,
                first_name=first_name,
                last_name=last_name,
                role_id=role_id,
                department=department,
                status=status,
                session_timeout=session_timeout,
                ip_address=ip_address,
                user_agent=user_agent
            )
        except Exception as e:
            logger.warning(f"Failed to create session in PostgreSQL: {e}")

        return session_id

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session from Redis (fast), fallback to PostgreSQL"""
        # Try Redis first
        session = self.redis.get_session(session_id)

        if session:
            return session

        # Fallback to PostgreSQL
        logger.debug(f"Session {session_id} not in Redis, checking PostgreSQL")
        session = self.postgres.get_session(session_id)

        if session:
            # Repopulate Redis cache
            try:
                self.redis.create_session(
                    user_id=session['user_id'],
                    email=session['email'],
                    first_name=session['first_name'],
                    last_name=session['last_name'],
                    role_id=session.get('role_id'),
                    department=session.get('department'),
                    status=session['status'],
                    session_timeout=3600,
                    ip_address=session.get('ip_address'),
                    user_agent=session.get('user_agent')
                )
            except Exception as e:
                logger.warning(f"Failed to repopulate Redis: {e}")

        return session

    def update_session_activity(self, session_id: str) -> bool:
        """Update activity in Redis only (performance)"""
        return self.redis.update_session_activity(session_id)

    def extend_session(self, session_id: str, additional_seconds: int = 3600) -> bool:
        """Extend session in both stores"""
        redis_success = self.redis.extend_session(session_id, additional_seconds)
        postgres_success = self.postgres.extend_session(session_id, additional_seconds)
        return redis_success or postgres_success

    def delete_session(self, session_id: str) -> bool:
        """Delete session from both stores"""
        redis_success = self.redis.delete_session(session_id)
        postgres_success = self.postgres.delete_session(session_id)
        return redis_success or postgres_success

    def delete_user_sessions(self, user_id: str) -> int:
        """Delete all user sessions from both stores"""
        redis_count = self.redis.delete_user_sessions(user_id)
        postgres_count = self.postgres.delete_user_sessions(user_id)
        return max(redis_count, postgres_count)

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions in both stores"""
        redis_count = self.redis.cleanup_expired_sessions()
        postgres_count = self.postgres.cleanup_expired_sessions()
        logger.info(f"Cleaned up {redis_count} Redis sessions, {postgres_count} PostgreSQL sessions")
        return redis_count + postgres_count

    def health_check(self) -> bool:
        """Check health of both stores"""
        redis_healthy = self.redis.health_check()
        postgres_healthy = self.postgres.health_check()

        if not redis_healthy:
            logger.warning("Redis health check failed")
        if not postgres_healthy:
            logger.warning("PostgreSQL health check failed")

        # At least Redis should be healthy for hybrid mode
        return redis_healthy


def get_session_store(postgres_session_manager=None, user_manager=None):
    """
    Factory function to get appropriate session store based on configuration

    Returns:
        SessionStoreProtocol: Redis, PostgreSQL, or Hybrid session store
    """
    session_store_type = os.getenv('SESSION_STORE', 'redis').lower()

    if session_store_type == 'redis':
        # Pure Redis mode
        from session_redis import get_redis_session_store
        store = get_redis_session_store()
        logger.info("Session store: Redis (pure)")
        return store

    elif session_store_type == 'postgres':
        # Pure PostgreSQL mode
        if not postgres_session_manager:
            raise ValueError("PostgreSQL session manager required for 'postgres' mode")

        adapter = PostgresSessionStoreAdapter(postgres_session_manager, user_manager)
        logger.info("Session store: PostgreSQL (pure)")
        return adapter

    elif session_store_type == 'hybrid':
        # Hybrid mode: Redis + PostgreSQL
        from session_redis import get_redis_session_store

        if not postgres_session_manager:
            raise ValueError("PostgreSQL session manager required for 'hybrid' mode")

        redis_store = get_redis_session_store()
        postgres_adapter = PostgresSessionStoreAdapter(postgres_session_manager, user_manager)
        hybrid_store = HybridSessionStore(redis_store, postgres_adapter)

        logger.info("Session store: Hybrid (Redis + PostgreSQL)")
        return hybrid_store

    else:
        raise ValueError(f"Invalid SESSION_STORE value: {session_store_type}. Use 'redis', 'postgres', or 'hybrid'")
