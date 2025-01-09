import socket
import argparse


class SIMPClient:
    def __init__(self, client_ip: str, daemon_port: int):
        self.client_ip = client_ip
        self.daemon_ip = None
        self.daemon_port = daemon_port  # 7778
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.client_ip, 7778))  # Bind to the specific IP address
        self.username = None
        self.connected_to_daemon = False
        self.connections = {}
        self.chat_started = False
        self.count = 0

        print(f"Client created, ready to connect to daemon at {self.daemon_ip}:{self.daemon_port}")

    # used to show menu for user actions
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
            if self.chat_started:
                self.chatting_mode()
                #chatting_mode
            else:
                print("\n=== SIMP Client Menu ===")
                print("1. Initiate a chat")
                print("2. Ping the daemon")
                print("3. Check for chat requests")
                print("4. Quit")
                choice = input("Enter your choice: ").strip()

                if choice == "1":
                    choice = input("Enter IP address of the user (daemon) you want to chat with: ").strip()
                    self.initiate_chat_request(choice)
                elif choice == "2":
                    self.ping_daemon()
                elif choice == "3":
                    self.check_for_chats()
                elif choice == "4":
                    print("Exiting...")
                    break
                else:
                    print("Invalid choice. Please try again.")


    # used to get handshake between client and daemon
    def connect_to_daemon(self, daemon_ip: str):
        """Send a connect request to the daemon."""
        if self.username is None:
            self.username = input("Enter your username: ").strip()
        print("Starting handshake...")

        # Send SYN to daemon
        syn_datagram = create_datagram(0x01, 0x02, 0x00, self.username)  # SYN
        self.socket.sendto(syn_datagram, (daemon_ip, self.daemon_port))
        print("Sent SYN to daemon")
        data, _ = self.socket.recvfrom(1024)
        parsed = parse_datagram(data)

        # Check if SYN-ACK received
        if parsed["type"] == 0x01 and parsed["operation"] == 0x06:  # SYN-ACK
            print("Received SYN-ACK from daemon")
            ack_datagram = create_datagram(0x01, 0x04, 0x00, self.username)  # ACK
            self.socket.sendto(ack_datagram, (daemon_ip, self.daemon_port))
            print("Sent ACK to daemon, handshake complete.")
            self.connected_to_daemon = True
            self.daemon_ip = daemon_ip
        else:
            print("Failed to establish connection.")

    # used to initiate chat request through the daemon
    def initiate_chat_request(self, receiver_ip: str):
        """Initiate a chat request to the daemon."""
        chat_request_datagram = create_datagram(0x01, 0x03, 0x00, self.username, receiver_ip)
        self.socket.sendto(chat_request_datagram, (self.daemon_ip, self.daemon_port))
        print(f"Sent chat request to {receiver_ip}:{self.daemon_port}")
        data, _ = self.socket.recvfrom(1024)
        parsed_datagram = parse_datagram(data)
        # Check if chat request accepted (ACK expected)
        if parsed_datagram["type"] == 0x01 and parsed_datagram["operation"] == 0x04:
            print(f"Received ACK from {parsed_datagram['user']}")
            print("Chat request accepted.")
            self.chat_started = True
            self.connections[receiver_ip] = parsed_datagram["user"]

        else:
            print("Chat request rejected.")

    # used to check for incoming chat requests
    def check_for_chats(self):
        """Listen for incoming messages from the daemon."""
        print("Checking for incoming messages...")
        chat_datagram = create_datagram(0x01, 0x07, 0x00, self.username)
        self.socket.sendto(chat_datagram, (self.daemon_ip, self.daemon_port))
        data, _ = self.socket.recvfrom(1024)
        parsed_datagram = parse_datagram(data)
        # Check if chat request exists (ACK expected)
        if parsed_datagram["type"] == 0x01 and parsed_datagram["operation"] == 0x04:
            print(f"Received chat request from {parsed_datagram['payload']}")
            print("Chat request received.")
            print("1. Accept")
            print("2. Reject")
            choice = input("Enter your choice: ").strip()
            if choice == "1":
                print("Chat accepted.")
                ack_datagram = create_datagram(0x01, 0x04, 0x00, self.username)
                self.socket.sendto(ack_datagram, (self.daemon_ip, self.daemon_port))
                print("Sent ACK to daemon")
                # wait syn-ack from daemon
                data, _ = self.socket.recvfrom(1024)
                parsed = parse_datagram(data)
                if parsed["type"] == 0x01 and parsed["operation"] == 0x04:
                    print(f"Received ACK from {parsed['user']}")
                    print("Connection established.")
                    self.connections[parsed["user"]] = parsed["payload"]
                    
                    self.listening_mode()

            elif choice == "2":
                print("Chat rejected.")
                fin_datagram = create_datagram(0x01, 0x08, 0x00, self.username, "Connection rejected")
                self.socket.sendto(fin_datagram, (self.daemon_ip, self.daemon_port))
            else:
                print("Invalid choice. Please try again.")



    def chatting_mode(self):
        """Enable the client to send messages to another client."""
        print("\n=== Chatting Mode ===")
        print("Type your messages below. Type 'exit' to leave the chat.")
        while self.chat_started:
            message = input("> ").strip()
            if message.lower() == 'exit':
                self.end_chat()
                break
            else:
                self.send_message(message)

    def listening_mode(self):
        """Listen for incoming messages from the daemon."""
        print("=== Listening for Messages ===")
        self.stop_listening = False
        while not self.stop_listening:
            try:
                data, _ = self.socket.recvfrom(1024)
                parsed_datagram = parse_datagram(data)
                if parsed_datagram["type"] == 0x02:  # Chat message
                    print(f"\nMessage from {parsed_datagram['user']}: {parsed_datagram['payload']}")
                    print("> ", end='', flush=True)
                elif parsed_datagram["operation"] == 0x08:  # Chat end notification
                    print("\nChat ended by the other user.")
                    self.chat_started = False
                    break
            except socket.timeout:
                continue

    def send_message(self, message: str):
        """Send a message to the daemon for forwarding."""
        if not self.chat_started:
            print("You are not in a chat.")
            return
        datagram = create_datagram(0x02, 0x00, 0x00, self.username, message)
        self.socket.sendto(datagram, (self.daemon_ip, self.daemon_port))
        print("Message sent.")

    def end_chat(self):
        """End the current chat session."""
        self.chat_started = False
        fin_datagram = create_datagram(0x01, 0x08, 0x00, self.username, "Chat ended")
        self.socket.sendto(fin_datagram, (self.daemon_ip, self.daemon_port))
        print("Chat ended.")


    def ping_daemon(self):
        """Send a ping request to the daemon."""
        ping_request = create_datagram(0x01, 0x05, 0x00, str(self.username), "ping")
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