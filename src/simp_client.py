import socket
import argparse
import threading

class SIMPClient:
    def __init__(self, client_ip: str, daemon_port: int):
        self.client_ip = client_ip
        self.daemon_ip = None
        self.daemon_port = daemon_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.client_ip, 7778))  # Bind to the specific IP address
        self.username = None
        self.connected_to_daemon = False
        self.connections = {}

        print(f"Client created, ready to connect to daemon at {self.daemon_ip}:{self.daemon_port}")

    def show_menu(self):
        """Display a menu for user actions."""
        while True:
            if not self.connected_to_daemon:
                print("You are not connected to a daemon.")
                print("\n=== SIMP Client Menu ===")
                print("1. Connect to daemon")
                print("2. Quit")

                choice = input("Enter your choice: ").strip()
                if choice == "1":
                    daemon_ip = input("Enter the IP of the Daemon you want to connect to: ").strip()
                    self.connect_to_daemon(daemon_ip)
                elif choice == "2":
                    print("Exiting...")
                    break
                else:
                    print("Invalid choice. Please try again.")
            else:
                print("\n=== SIMP Client Menu ===")
                print("1. Initiate a chat")
                print("2. Ping the daemon")
                print("3. Listen for incoming messages")
                print("4. Quit")
                choice = input("Enter your choice: ").strip()

                if choice == "1":
                    print("Chat feature not implemented yet.")
                elif choice == "2":
                    self.ping_daemon()
                elif choice == "3":
                    self.listen_for_messages()
                elif choice == "4":
                    print("Exiting...")
                    break
                else:
                    print("Invalid choice. Please try again.")

    def connect_to_daemon(self, daemon_ip: str):
        """Send a connect request to the daemon."""
        if self.username is None:
            self.username = input("Enter your username: ").strip()
        print("Starting handshake...")
        syn_datagram = create_datagram(0x01, 0x02, 0, self.username)  # SYN
        self.socket.sendto(syn_datagram, (daemon_ip, self.daemon_port))
        print("Sent SYN to daemon")
        data, _ = self.socket.recvfrom(1024)
        parsed = parse_datagram(data)
        if parsed["type"] == 0x01 and parsed["operation"] == 0x06:  # SYN-ACK
            print("Received SYN-ACK from daemon")
            ack_datagram = create_datagram(0x01, 0x04, 0, "client1")  # ACK
            self.socket.sendto(ack_datagram, (daemon_ip, self.daemon_port))
            print("Sent ACK to daemon, handshake complete.")
            self.connected_to_daemon = True
            self.daemon_ip = daemon_ip
        else:
            print("Failed to establish connection.")

    def listen_for_messages(self):
        """Listen for incoming messages from the daemon."""
        print("Listening for incoming messages...")
        data, _ = self.socket.recvfrom(1024)
        parsed_datagram = parse_datagram(data)
        print(f"Received data: {parsed_datagram}")
        if parsed_datagram["type"] == 0x01 and parsed_datagram["operation"] == 0x02:
            print(f"Received SYN from daemon: {parsed_datagram}")
        elif parsed_datagram["type"] == 0x01 and parsed_datagram["operation"] == 0x04:
            print("Connection rejected by daemon (FIN)")

    def ping_daemon(self):
        """Send a ping request to the daemon."""
        ping_request = create_datagram(0x01, 0x05, 0, str(self.username), "ping")
        self.socket.sendto(ping_request, (self.daemon_ip, self.daemon_port))
        print("Ping request sent to daemon")
        data, _ = self.socket.recvfrom(1024)
        parsed_datagram = parse_datagram(data)
        print(f"Received data: {parsed_datagram['payload']}")

# Datagram functions
def create_datagram(datagram_type: int, operation: int, sequence: int, user: str, payload: str = "") -> bytes:
    user_field = user.ljust(32)[:32].encode('ascii')
    payload_length = len(payload)
    header = (
        datagram_type.to_bytes(1, 'big') +
        operation.to_bytes(1, 'big') +
        sequence.to_bytes(1, 'big') +
        user_field +
        payload_length.to_bytes(4, 'big')
    )
    return header + payload.encode('ascii')

def parse_datagram(data: bytes) -> dict:
    datagram_type = data[0]
    operation = data[1]
    sequence = data[2]
    user = data[3:35].decode('ascii').strip()
    payload_length = int.from_bytes(data[35:39], 'big')
    payload = data[39:39 + payload_length].decode('ascii')
    return {
        "type": datagram_type,
        "operation": operation,
        "sequence": sequence,
        "user": user,
        "payload_length": payload_length,
        "payload": payload
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIMP Client")
    parser.add_argument("client_ip", type=str, help="Client IP address")
    args = parser.parse_args()

    client = SIMPClient(args.client_ip,7778)
    client.show_menu()