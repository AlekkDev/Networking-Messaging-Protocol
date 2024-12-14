import socket
import threading

# Setup Functions
def start_daemon(ip_address: str, port: int) -> None:
    """Starts the daemon to listen for incoming connections."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((socket.gethostname(), 7777))


# Connection Management
def handle_connection_request(client_address: tuple) -> None:
    """Handles an incoming connection request from a client."""
    pass
def send_connection_request(host,port, sock) -> None:
    """Sends a connection request to the specified IP address."""
    sock.connect((host, port))

def accept_connection(conn,addr) -> None:
    """Sends a SYN+ACK response to establish a connection."""


def reject_connection(client_address: tuple) -> None:
    """Sends a FIN response to reject a connection request."""
    pass

# Chat Management
def handle_chat_message(client_address: tuple, message: str) -> None:
    """Handles incoming chat messages."""
    pass

def send_acknowledgement(client_address: tuple) -> None:
    """Sends an ACK message to acknowledge received data."""
    pass

# Utility
def log_event(event: str) -> None:
    """Logs events such as connections and messages."""
    pass

def resend_message(message: bytes, client_address: tuple) -> None:
    """Resends a message if no ACK is received within the timeout."""
    pass
