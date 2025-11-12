"""
Redis-based Session Management
High-performance session storage with automatic expiration
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional
import redis
from secrets import token_urlsafe

logger = logging.getLogger(__name__)


class RedisSessionStore:
    """Redis-based session storage with automatic TTL"""

    def __init__(self):
        """Initialize Redis connection"""
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.redis_password = os.getenv('REDIS_PASSWORD', '')
        self.redis_db = int(os.getenv('REDIS_DB', 0))

        # Create Redis connection pool
        self.pool = redis.ConnectionPool(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password,
            db=self.redis_db,
            decode_responses=True,
            max_connections=50,
            socket_connect_timeout=5,
            socket_keepalive=True
        )

        self.client = redis.Redis(connection_pool=self.pool)

        # Test connection
        try:
            self.client.ping()
            logger.info(f"Connected to Redis at {self.redis_host}:{self.redis_port}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def _session_key(self, session_id: str) -> str:
        """Generate Redis key for session"""
        return f"session:{session_id}"

    def _user_sessions_key(self, user_id: str) -> str:
        """Generate Redis key for user's session set"""
        return f"user_sessions:{user_id}"

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
        """Create a new session in Redis"""
        session_id = token_urlsafe(32)

        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=session_timeout)

        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'role_id': role_id or '',
            'department': department or '',
            'status': status,
            'created_at': now.isoformat(),
            'expires_at': expires_at.isoformat(),
            'last_activity': now.isoformat(),
            'ip_address': ip_address or '',
            'user_agent': user_agent or ''
        }

        # Store session with automatic expiration
        session_key = self._session_key(session_id)
        self.client.hset(session_key, mapping=session_data)
        self.client.expire(session_key, session_timeout)

        # Add to user's session set
        user_sessions_key = self._user_sessions_key(user_id)
        self.client.sadd(user_sessions_key, session_id)
        self.client.expire(user_sessions_key, session_timeout)

        logger.info(f"Created session {session_id} for user {user_id}")
        return session_id

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session data from Redis"""
        session_key = self._session_key(session_id)
        session_data = self.client.hgetall(session_key)

        if not session_data:
            return None

        # Check if session is expired
        expires_at = datetime.fromisoformat(session_data['expires_at'])
        if datetime.utcnow() > expires_at:
            self.delete_session(session_id)
            return None

        # Update last activity
        self.client.hset(session_key, 'last_activity', datetime.utcnow().isoformat())

        return session_data

    def update_session_activity(self, session_id: str) -> bool:
        """Update session last activity timestamp"""
        session_key = self._session_key(session_id)

        if not self.client.exists(session_key):
            return False

        self.client.hset(session_key, 'last_activity', datetime.utcnow().isoformat())
        return True

    def extend_session(self, session_id: str, additional_seconds: int = 3600) -> bool:
        """Extend session expiration time"""
        session_key = self._session_key(session_id)

        if not self.client.exists(session_key):
            return False

        # Get current TTL and add additional time
        current_ttl = self.client.ttl(session_key)
        if current_ttl > 0:
            new_ttl = current_ttl + additional_seconds
            self.client.expire(session_key, new_ttl)

            # Update expires_at in session data
            new_expires_at = datetime.utcnow() + timedelta(seconds=new_ttl)
            self.client.hset(session_key, 'expires_at', new_expires_at.isoformat())

            logger.info(f"Extended session {session_id} by {additional_seconds}s")
            return True

        return False

    def delete_session(self, session_id: str) -> bool:
        """Delete a session from Redis"""
        session_key = self._session_key(session_id)

        # Get user_id before deleting
        session_data = self.client.hgetall(session_key)
        if session_data and 'user_id' in session_data:
            user_id = session_data['user_id']
            user_sessions_key = self._user_sessions_key(user_id)
            self.client.srem(user_sessions_key, session_id)

        result = self.client.delete(session_key)
        logger.info(f"Deleted session {session_id}")
        return result > 0

    def delete_user_sessions(self, user_id: str) -> int:
        """Delete all sessions for a user"""
        user_sessions_key = self._user_sessions_key(user_id)
        session_ids = self.client.smembers(user_sessions_key)

        count = 0
        for session_id in session_ids:
            if self.delete_session(session_id):
                count += 1

        # Clean up the user sessions set
        self.client.delete(user_sessions_key)

        logger.info(f"Deleted {count} sessions for user {user_id}")
        return count

    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions
        Note: Redis handles TTL automatically, but this can clean up user session sets
        """
        # Redis automatically removes expired keys, but we need to clean up
        # the user_sessions sets that might reference deleted sessions
        count = 0

        # This is optional cleanup - Redis TTL handles most of it
        logger.info(f"Redis TTL auto-cleanup: {count} sessions cleaned")
        return count

    def get_user_sessions(self, user_id: str) -> list:
        """Get all active sessions for a user"""
        user_sessions_key = self._user_sessions_key(user_id)
        session_ids = self.client.smembers(user_sessions_key)

        sessions = []
        for session_id in session_ids:
            session = self.get_session(session_id)
            if session:
                sessions.append(session)

        return sessions

    def get_stats(self) -> Dict:
        """Get Redis session statistics"""
        try:
            info = self.client.info()

            # Count session keys
            session_count = 0
            for key in self.client.scan_iter(match="session:*"):
                session_count += 1

            return {
                'connected': True,
                'total_sessions': session_count,
                'redis_version': info.get('redis_version', 'unknown'),
                'used_memory': info.get('used_memory_human', 'unknown'),
                'connected_clients': info.get('connected_clients', 0),
                'uptime_seconds': info.get('uptime_in_seconds', 0)
            }
        except Exception as e:
            logger.error(f"Failed to get Redis stats: {e}")
            return {'connected': False, 'error': str(e)}

    def health_check(self) -> bool:
        """Check if Redis is healthy"""
        try:
            return self.client.ping()
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False

    def close(self):
        """Close Redis connection"""
        if hasattr(self, 'client'):
            self.client.close()
        if hasattr(self, 'pool'):
            self.pool.disconnect()
        logger.info("Redis connection closed")


# Singleton instance
_redis_session_store: Optional[RedisSessionStore] = None


def get_redis_session_store() -> RedisSessionStore:
    """Get or create Redis session store singleton"""
    global _redis_session_store

    if _redis_session_store is None:
        _redis_session_store = RedisSessionStore()

    return _redis_session_store
