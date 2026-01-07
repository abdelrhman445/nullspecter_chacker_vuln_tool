"""
Session management for NullSpecter
Handles authentication, cookies, and session persistence
"""

import json
import pickle
import hashlib
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta


class SessionManager:
    """Manages scanning sessions with persistence"""
    
    def __init__(self, session_dir: str = "./sessions"):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(exist_ok=True)
        self.current_session = None
        self.sessions = {}
    
    def create_session(self, name: str, config: Dict[str, Any]) -> str:
        """Create a new scanning session"""
        session_id = hashlib.sha256(
            f"{name}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        session_data = {
            'id': session_id,
            'name': name,
            'created_at': datetime.now().isoformat(),
            'config': config,
            'targets': [],
            'results': {},
            'stats': {
                'total_scans': 0,
                'vulnerabilities_found': 0,
                'last_scan': None
            }
        }
        
        # Save session to file
        session_file = self.session_dir / f"{session_id}.json"
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        self.current_session = session_id
        self.sessions[session_id] = session_data
        
        return session_id
    
    def load_session(self, session_id: str) -> bool:
        """Load an existing session"""
        session_file = self.session_dir / f"{session_id}.json"
        
        if not session_file.exists():
            return False
        
        with open(session_file, 'r') as f:
            session_data = json.load(f)
        
        self.sessions[session_id] = session_data
        self.current_session = session_id
        
        return True
    
    def save_session(self, session_id: str = None):
        """Save session to disk"""
        if session_id is None:
            session_id = self.current_session
        
        if session_id not in self.sessions:
            return False
        
        session_file = self.session_dir / f"{session_id}.json"
        with open(session_file, 'w') as f:
            json.dump(self.sessions[session_id], f, indent=2)
        
        return True
    
    def update_session(self, updates: Dict[str, Any], session_id: str = None):
        """Update session data"""
        if session_id is None:
            session_id = self.current_session
        
        if session_id not in self.sessions:
            return False
        
        self.sessions[session_id].update(updates)
        self.save_session(session_id)
        
        return True
    
    def add_scan_result(self, target: str, result: Dict[str, Any], session_id: str = None):
        """Add scan result to session"""
        if session_id is None:
            session_id = self.current_session
        
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        # Add target if not already in list
        if target not in session['targets']:
            session['targets'].append(target)
        
        # Store result
        session['results'][target] = {
            'scan_time': datetime.now().isoformat(),
            'result': result
        }
        
        # Update statistics
        session['stats']['total_scans'] += 1
        session['stats']['vulnerabilities_found'] += len(result.get('vulnerabilities', []))
        session['stats']['last_scan'] = datetime.now().isoformat()
        
        self.save_session(session_id)
        
        return True
    
    def get_session(self, session_id: str = None) -> Optional[Dict[str, Any]]:
        """Get session data"""
        if session_id is None:
            session_id = self.current_session
        
        return self.sessions.get(session_id)
    
    def list_sessions(self) -> list:
        """List all available sessions"""
        sessions = []
        
        for session_file in self.session_dir.glob("*.json"):
            try:
                with open(session_file, 'r') as f:
                    session_data = json.load(f)
                    sessions.append({
                        'id': session_data['id'],
                        'name': session_data['name'],
                        'created_at': session_data['created_at'],
                        'stats': session_data['stats']
                    })
            except:
                continue
        
        return sessions
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        session_file = self.session_dir / f"{session_id}.json"
        
        if session_file.exists():
            session_file.unlink()
        
        if session_id in self.sessions:
            del self.sessions[session_id]
        
        if self.current_session == session_id:
            self.current_session = None
        
        return True


class AuthManager:
    """Handles authentication for scans"""
    
    def __init__(self):
        self.auth_methods = {}
        self.current_auth = None
    
    def add_basic_auth(self, username: str, password: str, name: str = "basic_auth"):
        """Add basic authentication"""
        import base64
        
        auth_string = f"{username}:{password}"
        encoded = base64.b64encode(auth_string.encode()).decode()
        
        self.auth_methods[name] = {
            'type': 'basic',
            'header': f"Basic {encoded}",
            'username': username,
            'password': password
        }
        
        return name
    
    def add_bearer_token(self, token: str, name: str = "bearer_token"):
        """Add bearer token authentication"""
        self.auth_methods[name] = {
            'type': 'bearer',
            'header': f"Bearer {token}",
            'token': token
        }
        
        return name
    
    def add_api_key(self, key: str, header_name: str = "X-API-Key", name: str = "api_key"):
        """Add API key authentication"""
        self.auth_methods[name] = {
            'type': 'api_key',
            'header': {header_name: key},
            'key': key,
            'header_name': header_name
        }
        
        return name
    
    def add_cookie_auth(self, cookies: Dict[str, str], name: str = "cookies"):
        """Add cookie-based authentication"""
        self.auth_methods[name] = {
            'type': 'cookies',
            'cookies': cookies
        }
        
        return name
    
    def get_auth_headers(self, auth_name: str = None) -> Dict[str, str]:
        """Get authentication headers for a method"""
        if auth_name is None:
            auth_name = self.current_auth
        
        if auth_name not in self.auth_methods:
            return {}
        
        auth = self.auth_methods[auth_name]
        
        if auth['type'] == 'basic':
            return {'Authorization': auth['header']}
        elif auth['type'] == 'bearer':
            return {'Authorization': auth['header']}
        elif auth['type'] == 'api_key':
            return auth['header']
        elif auth['type'] == 'cookies':
            return {}
        
        return {}
    
    def get_auth_cookies(self, auth_name: str = None) -> Dict[str, str]:
        """Get authentication cookies for a method"""
        if auth_name is None:
            auth_name = self.current_auth
        
        if auth_name not in self.auth_methods:
            return {}
        
        auth = self.auth_methods[auth_name]
        
        if auth['type'] == 'cookies':
            return auth['cookies']
        
        return {}


# Global session manager
session_manager = SessionManager()
auth_manager = AuthManager()