import socket
import argparse

class SIMPClient:
    def __init__(self, daemon_ip: str, daemon_port: int):
        self.client_ip = daemon_ip
        self.daemon_ip = daemon_ip
        self.daemon_port = daemon_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.client_ip, 0))  # Bind to the specific IP address
        self.username = None
        print(f"Client created, ready to connect to daemon at {self.daemon_ip}:{self.daemon_port}")

    def show_menu(self):
        """Display a menu for user actions."""
        while True:
            print("\n=== SIMP Client Menu ===")
            print("1. Connect to other clients")
            print("2. Wait for incoming connections")
            print("3. Ping Daemon")
            print("4. Quit")

            choice = input("Enter your choice: ").strip()
            if choice == "1":
                if self.username is None:
                    self.username = input("Enter your username: ").strip()
                other_client_ip = input("Enter the IP of the client you want to chat with: ").strip()
                self.connect(other_client_ip)
            elif choice == "2":
                self.wait_for_connection()
            elif choice == "3":
                self.ping_daemon()
            elif choice == "4":
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

    def connect(self, other_client_ip: str):
        """Send a connect request to the daemon."""
        connect_request = create_datagram(0x01, 0x02, 0, str(self.username), other_client_ip)
        self.socket.sendto(connect_request, (self.daemon_ip, self.daemon_port))
        print("Connect request sent to daemon")

    def wait_for_connection(self):
        """Send a wait-for-connection request to the daemon."""
        wait_request = create_datagram(0x01, 0x03, 0, str(self.username))
        self.socket.sendto(wait_request, (self.daemon_ip, self.daemon_port))
        print("Wait-for-connection request sent to daemon")

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
    parser.add_argument("daemon_ip", type=str, help="Daemon IP address")
    args = parser.parse_args()

    client = SIMPClient(args.daemon_ip, 7778)
    client.show_menu()