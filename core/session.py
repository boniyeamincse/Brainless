"""
Brainless Framework - Session Manager
=====================================

Manages active sessions, session interaction, and session lifecycle
for the Brainless Framework.

Author: Brainless Security Team
"""

import time
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from core.logger import LoggerMixin


@dataclass
class Session:
    """Represents an active session"""
    id: str
    session_type: str
    host: str
    port: int
    status: str = "active"
    created: str = None
    last_activity: str = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.created is None:
            self.created = datetime.now().isoformat()
        if self.last_activity is None:
            self.last_activity = datetime.now().isoformat()
        if self.metadata is None:
            self.metadata = {}
    
    def update_activity(self):
        """Update the last activity timestamp"""
        self.last_activity = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary"""
        return asdict(self)


class SessionManager(LoggerMixin):
    """
    Manages active sessions for the Brainless Framework
    
    Features:
    - Session creation and tracking
    - Session cleanup and timeout handling
    - Session interaction
    - Session persistence (optional)
    """
    
    def __init__(self, config=None):
        """
        Initialize the session manager
        
        Args:
            config: Framework configuration
        """
        super().__init__('SessionManager')
        
        self.config = config
        self.sessions: Dict[str, Session] = {}
        self.session_counter = 1
        self.lock = threading.Lock()
        
        # Session cleanup settings
        self.session_timeout = 3600  # 1 hour default
        self.cleanup_interval = 300  # 5 minutes
        
        if config:
            try:
                self.session_timeout = config.getint('handlers', 'session_timeout', fallback=3600)
                self.cleanup_interval = config.getint('handlers', 'cleanup_interval', fallback=300)
            except:
                pass
        
        # Start cleanup thread
        self._start_cleanup_thread()
        
        self.info("Session manager initialized")
    
    def _start_cleanup_thread(self):
        """Start the background cleanup thread"""
        def cleanup_worker():
            while True:
                try:
                    self._cleanup_expired_sessions()
                    time.sleep(self.cleanup_interval)
                except Exception as e:
                    self.error(f"Session cleanup error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        self.debug("Session cleanup thread started")
    
    def _cleanup_expired_sessions(self):
        """Remove expired sessions"""
        with self.lock:
            current_time = datetime.now()
            expired_sessions = []
            
            for session_id, session in self.sessions.items():
                try:
                    last_activity = datetime.fromisoformat(session.last_activity)
                    if current_time - last_activity > timedelta(seconds=self.session_timeout):
                        expired_sessions.append(session_id)
                except Exception as e:
                    self.warning(f"Error checking session {session_id}: {e}")
            
            for session_id in expired_sessions:
                self.remove_session(session_id)
                self.info(f"Cleaned up expired session: {session_id}")
    
    def create_session(self, session_type: str = "shell", **kwargs) -> str:
        """
        Create a new session
        
        Args:
            session_type (str): Type of session (shell, meterpreter, etc.)
            **kwargs: Additional session parameters
        
        Returns:
            Session ID
        """
        with self.lock:
            session_id = f"{session_type}_{self.session_counter:04d}"
            self.session_counter += 1
            
            # Extract session parameters
            host = kwargs.get('host', 'unknown')
            port = kwargs.get('port', 0)
            metadata = kwargs.get('metadata', {})
            
            # Create session
            session = Session(
                id=session_id,
                session_type=session_type,
                host=host,
                port=port,
                metadata=metadata
            )
            
            self.sessions[session_id] = session
            
            self.info(f"Created session {session_id} ({session_type}) for {host}:{port}")
            return session_id
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Get a session by ID
        
        Args:
            session_id (str): Session identifier
        
        Returns:
            Session object or None if not found
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if session:
                session.update_activity()
            return session
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all active sessions
        
        Returns:
            List of session dictionaries
        """
        with self.lock:
            session_list = []
            for session in self.sessions.values():
                session_list.append(session.to_dict())
            return session_list
    
    def remove_session(self, session_id: str):
        """
        Remove a session
        
        Args:
            session_id (str): Session identifier
        """
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                session.status = "closed"
                del self.sessions[session_id]
                self.info(f"Removed session {session_id}")
            else:
                raise ValueError(f"Session not found: {session_id}")
    
    def update_session(self, session_id: str, **kwargs):
        """
        Update session information
        
        Args:
            session_id (str): Session identifier
            **kwargs: Session fields to update
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"Session not found: {session_id}")
            
            # Update fields
            for key, value in kwargs.items():
                if hasattr(session, key):
                    setattr(session, key, value)
            
            session.update_activity()
            self.debug(f"Updated session {session_id}")
    
    def get_session_count(self) -> int:
        """Get the number of active sessions"""
        with self.lock:
            return len(self.sessions)
    
    def get_sessions_by_type(self, session_type: str) -> List[Session]:
        """
        Get all sessions of a specific type
        
        Args:
            session_type (str): Type of sessions to retrieve
        
        Returns:
            List of sessions
        """
        with self.lock:
            sessions = []
            for session in self.sessions.values():
                if session.session_type == session_type:
                    sessions.append(session)
            return sessions
    
    def interact_with_session(self, session_id: str) -> bool:
        """
        Mark a session as being interacted with
        
        Args:
            session_id (str): Session identifier
        
        Returns:
            True if session found and updated, False otherwise
        """
        session = self.get_session(session_id)
        if session:
            session.status = "interacting"
            session.update_activity()
            return True
        return False
    
    def end_session_interaction(self, session_id: str):
        """
        Mark a session as no longer being interacted with
        
        Args:
            session_id (str): Session identifier
        """
        session = self.get_session(session_id)
        if session:
            session.status = "active"
            session.update_activity()
    
    def cleanup(self):
        """Clean up all sessions and stop background threads"""
        with self.lock:
            session_count = len(self.sessions)
            self.sessions.clear()
        
        self.info(f"Cleaned up {session_count} sessions")
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get statistics about active sessions"""
        with self.lock:
            stats = {
                'total_sessions': len(self.sessions),
                'session_types': {},
                'oldest_session': None,
                'newest_session': None
            }
            
            if self.sessions:
                # Count session types
                for session in self.sessions.values():
                    session_type = session.session_type
                    stats['session_types'][session_type] = stats['session_types'].get(session_type, 0) + 1
                
                # Find oldest and newest sessions
                sorted_sessions = sorted(self.sessions.values(), key=lambda s: s.created)
                stats['oldest_session'] = sorted_sessions[0].created
                stats['newest_session'] = sorted_sessions[-1].created
            
            return stats