#!/usr/bin/env python3
"""
Multi Handler Listener
======================

Advanced listener that can handle multiple payload types and sessions.
Supports reverse shells, meterpreter connections, and custom payloads.

Author: Brainless Security Team
Module: listeners/multi_handler
Type: listener
Rank: excellent
"""

import os
import sys
import socket
import threading
import ssl
import json
import base64
import time
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.logger import LoggerMixin

NAME = "Multi Handler"
DESCRIPTION = "Advanced listener for handling multiple payload types and sessions"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "listener"

class MultiHandler(LoggerMixin):
    """
    Multi-handler for accepting connections from various payloads
    """
    
    def __init__(self):
        super().__init__('MultiHandler')
        self.lhost = '0.0.0.0'
        self.lport = 4444
        self.use_ssl = False
        self.cert_file = None
        self.key_file = None
        self.timeout = 60
        self.max_sessions = 50
        self.sessions = {}
        self.running = False
        self.server_socket = None
        
        # Session handlers for different payload types
        self.payload_handlers = {
            'reverse_tcp': self.handle_reverse_tcp,
            'meterpreter': self.handle_meterpreter,
            'custom': self.handle_custom
        }
    
    def set_option(self, option: str, value: str):
        """Set handler options"""
        if option.lower() == 'lhost':
            self.lhost = value
        elif option.lower() == 'lport':
            self.lport = int(value)
        elif option.lower() == 'use_ssl':
            self.use_ssl = value.lower() == 'true'
        elif option.lower() == 'cert_file':
            self.cert_file = value
        elif option.lower() == 'key_file':
            self.key_file = value
        elif option.lower() == 'timeout':
            self.timeout = int(value)
        elif option.lower() == 'max_sessions':
            self.max_sessions = int(value)
    
    def get_options(self) -> dict:
        """Get handler options"""
        return {
            'LHOST': {'description': 'Local host to listen on', 'required': True, 'default': '0.0.0.0'},
            'LPORT': {'description': 'Local port to listen on', 'required': True, 'default': '4444'},
            'USE_SSL': {'description': 'Use SSL/TLS encryption', 'required': False, 'default': 'false'},
            'CERT_FILE': {'description': 'SSL certificate file', 'required': False, 'default': ''},
            'KEY_FILE': {'description': 'SSL private key file', 'required': False, 'default': ''},
            'TIMEOUT': {'description': 'Session timeout in seconds', 'required': False, 'default': '60'},
            'MAX_SESSIONS': {'description': 'Maximum concurrent sessions', 'required': False, 'default': '50'}
        }
    
    def create_ssl_context(self):
        """Create SSL context for encrypted connections"""
        if not self.use_ssl:
            return None
        
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(self.cert_file, self.key_file)
            return context
        except Exception as e:
            self.error(f"Failed to create SSL context: {e}")
            return None
    
    def start_server(self):
        """Start the listening server"""
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind and listen
            self.server_socket.bind((self.lhost, self.lport))
            self.server_socket.listen(5)
            
            self.info(f"Listening on {self.lhost}:{self.lport}")
            if self.use_ssl:
                self.info("SSL/TLS encryption enabled")
            
            self.running = True
            
            # Accept connections
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.info(f"Connection from {client_address[0]}:{client_address[1]}")
                    
                    # Handle connection in separate thread
                    threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    ).start()
                    
                except socket.error:
                    if self.running:
                        break
            
        except Exception as e:
            self.error(f"Server error: {e}")
    
    def handle_client(self, client_socket, client_address):
        """Handle incoming client connection"""
        try:
            # Wrap with SSL if enabled
            if self.use_ssl:
                context = self.create_ssl_context()
                if context:
                    client_socket = context.wrap_socket(client_socket, server_side=True)
            
            # Set timeout
            client_socket.settimeout(self.timeout)
            
            # Detect payload type
            payload_type = self.detect_payload_type(client_socket)
            self.info(f"Detected payload type: {payload_type} from {client_address[0]}")
            
            # Handle based on payload type
            if payload_type in self.payload_handlers:
                session_id = self.create_session(client_address, payload_type)
                self.payload_handlers[payload_type](client_socket, session_id)
            else:
                self.warning(f"Unknown payload type from {client_address[0]}")
                client_socket.close()
        
        except Exception as e:
            self.error(f"Error handling client {client_address[0]}: {e}")
            try:
                client_socket.close()
            except:
                pass
    
    def detect_payload_type(self, client_socket) -> str:
        """Detect the type of payload connecting"""
        try:
            # Try to read initial data to detect payload type
            client_socket.settimeout(5)
            data = client_socket.recv(1024)
            client_socket.settimeout(self.timeout)
            
            if not data:
                return 'custom'
            
            data_str = data.decode('utf-8', errors='ignore')
            
            # Detect based on initial data patterns
            if 'meterpreter' in data_str.lower():
                return 'meterpreter'
            elif 'reverse_tcp' in data_str.lower():
                return 'reverse_tcp'
            elif data_str.startswith('{') and 'type' in data_str:
                return 'meterpreter'  # JSON-based protocol
            else:
                return 'reverse_tcp'  # Default assumption
        
        except:
            return 'custom'
    
    def create_session(self, client_address, payload_type) -> str:
        """Create a new session"""
        session_id = f"{client_address[0]}:{client_address[1]}:{int(time.time())}"
        
        session = {
            'id': session_id,
            'ip': client_address[0],
            'port': client_address[1],
            'type': payload_type,
            'connected_at': time.time(),
            'last_activity': time.time(),
            'active': True
        }
        
        self.sessions[session_id] = session
        self.info(f"Created session {session_id} ({payload_type})")
        
        return session_id
    
    def handle_reverse_tcp(self, client_socket, session_id):
        """Handle reverse TCP shell connection"""
        try:
            session = self.sessions[session_id]
            
            # Interactive shell loop
            while session['active']:
                try:
                    # Send prompt
                    client_socket.send(b"$ ")
                    
                    # Receive command
                    command = b""
                    while not command.endswith(b"\n"):
                        data = client_socket.recv(1)
                        if not data:
                            break
                        command += data
                    
                    if not command:
                        break
                    
                    # Execute command
                    command_str = command.decode('utf-8', errors='ignore').strip()
                    if command_str.lower() in ['exit', 'quit']:
                        break
                    
                    # In a real implementation, you'd execute the command here
                    # For now, just echo back
                    response = f"Command executed: {command_str}\n"
                    client_socket.send(response.encode())
                    
                    session['last_activity'] = time.time()
                
                except socket.timeout:
                    # Check if session should be closed
                    if time.time() - session['last_activity'] > self.timeout:
                        break
                    continue
        
        except Exception as e:
            self.error(f"Error in reverse TCP handler: {e}")
        
        finally:
            self.close_session(session_id)
            try:
                client_socket.close()
            except:
                pass
    
    def handle_meterpreter(self, client_socket, session_id):
        """Handle meterpreter-style connection"""
        try:
            session = self.sessions[session_id]
            
            while session['active']:
                try:
                    # Receive JSON command
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    # Decrypt if needed
                    data_str = data.decode('utf-8', errors='ignore')
                    
                    try:
                        command_data = json.loads(data_str)
                    except:
                        # Try base64 decode first
                        try:
                            decoded = base64.b64decode(data_str).decode()
                            command_data = json.loads(decoded)
                        except:
                            continue
                    
                    # Process command
                    response = self.process_meterpreter_command(command_data, session)
                    
                    # Send response
                    response_data = json.dumps(response)
                    client_socket.send(response_data.encode())
                    
                    session['last_activity'] = time.time()
                
                except socket.timeout:
                    if time.time() - session['last_activity'] > self.timeout:
                        break
                    continue
        
        except Exception as e:
            self.error(f"Error in meterpreter handler: {e}")
        
        finally:
            self.close_session(session_id)
            try:
                client_socket.close()
            except:
                pass
    
    def process_meterpreter_command(self, command_data: dict, session: dict) -> dict:
        """Process meterpreter-style commands"""
        cmd_type = command_data.get('type', 'unknown')
        
        if cmd_type == 'beacon':
            return {
                'status': 'alive',
                'session_info': {
                    'id': session['id'],
                    'ip': session['ip'],
                    'type': session['type']
                }
            }
        
        elif cmd_type == 'execute':
            command = command_data.get('command', '')
            # In a real implementation, execute the command
            return {
                'status': 'executed',
                'command': command,
                'output': f'Executed: {command}'
            }
        
        elif cmd_type == 'info':
            return {
                'status': 'success',
                'system_info': {
                    'platform': 'linux',
                    'hostname': 'target-host',
                    'username': 'target-user'
                }
            }
        
        elif cmd_type == 'upload':
            filename = command_data.get('filename', '')
            content = command_data.get('content', '')
            return {
                'status': 'uploaded',
                'filename': filename,
                'size': len(content)
            }
        
        elif cmd_type == 'download':
            filename = command_data.get('filename', '')
            # In a real implementation, read the file
            return {
                'status': 'success',
                'filename': filename,
                'content': base64.b64encode(b'file content').decode()
            }
        
        else:
            return {'status': 'unknown_command', 'type': cmd_type}
    
    def handle_custom(self, client_socket, session_id):
        """Handle custom payload connection"""
        try:
            # For custom payloads, just maintain the connection
            session = self.sessions[session_id]
            
            while session['active']:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    # Process custom data
                    self.process_custom_data(data, session_id)
                    session['last_activity'] = time.time()
                
                except socket.timeout:
                    if time.time() - session['last_activity'] > self.timeout:
                        break
                    continue
        
        except Exception as e:
            self.error(f"Error in custom handler: {e}")
        
        finally:
            self.close_session(session_id)
            try:
                client_socket.close()
            except:
                pass
    
    def process_custom_data(self, data: bytes, session_id: str):
        """Process custom payload data"""
        # Custom data processing logic would go here
        self.debug(f"Received custom data from session {session_id}")
    
    def close_session(self, session_id: str):
        """Close a session"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session['active'] = False
            session['disconnected_at'] = time.time()
            
            duration = session['disconnected_at'] - session['connected_at']
            self.info(f"Session {session_id} closed (duration: {duration:.2f}s)")
            
            del self.sessions[session_id]
    
    def list_sessions(self) -> list:
        """List all active sessions"""
        session_list = []
        for session_id, session in self.sessions.items():
            session_list.append({
                'id': session['id'],
                'ip': session['ip'],
                'port': session['port'],
                'type': session['type'],
                'connected_at': session['connected_at'],
                'last_activity': session['last_activity'],
                'active': session['active']
            })
        return session_list
    
    def stop_server(self):
        """Stop the listening server"""
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Close all sessions
        for session_id in list(self.sessions.keys()):
            self.close_session(session_id)
        
        self.info("Server stopped")
    
    def run(self) -> dict:
        """
        Start the multi-handler
        """
        try:
            self.info(f"Starting multi-handler on {self.lhost}:{self.lport}")
            
            # Start server in separate thread
            server_thread = threading.Thread(target=self.start_server, daemon=True)
            server_thread.start()
            
            # Keep main thread alive
            try:
                while self.running:
                    time.sleep(1)
                    
                    # Clean up old sessions
                    self.cleanup_sessions()
                    
            except KeyboardInterrupt:
                self.info("Stopping multi-handler...")
                self.stop_server()
            
            return {'success': True, 'message': 'Multi-handler started successfully'}
            
        except Exception as e:
            self.error(f"Failed to start multi-handler: {e}")
            return {'success': False, 'message': f'Startup failed: {str(e)}'}
    
    def cleanup_sessions(self):
        """Clean up expired sessions"""
        current_time = time.time()
        
        for session_id in list(self.sessions.keys()):
            session = self.sessions[session_id]
            
            if current_time - session['last_activity'] > self.timeout:
                self.close_session(session_id)


def run(options: dict = None) -> dict:
    """
    Entry point for the listener
    """
    handler = MultiHandler()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            handler.set_option(key, value)
    
    return handler.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'LHOST': '0.0.0.0',
        'LPORT': '4444',
        'USE_SSL': 'false',
        'TIMEOUT': '60',
        'MAX_SESSIONS': '50'
    }
    
    result = run(options)
    print(result)