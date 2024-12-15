import socket
import threading
import time


class Client:
    def __init__(self, daemon_ip: str):
        self.daemon_ip = daemon_ip
        self.daemon_port = 7778
        self.username = ""
        self.running = True

    def start(self):
        """Starts the client."""
        self.username = input("Enter your username: ").strip()

        print("Connecting to daemon...")

        # Thread to handle incoming messages from the daemon
        threading.Thread(target=self.receive_updates, daemon=True).start()

        # Main loop for user interaction
        while self.running:
            self.display_menu()
            command = input("> ").strip().lower()
            self.handle_command(command)
    def display_menu(self):
        """Displays the menu for user actions."""
        print("\n=== SIMP Client Menu ===")
        print("1. Start a new chat")
        print("2. Wait for incoming chat requests")
        print("3. Quit")

    def handle_command(self, command: str):
        """Handles user input commands."""
        if command == "1":
            remote_ip = input("Enter the IP address of the user you want to chat with: ").strip()
            self.send_to_daemon(f"connect {remote_ip}")
        elif command == "2":
            print("Waiting for incoming chat requests...")
        elif command == "3":
            self.send_to_daemon("quit")
            self.running = False
        else:
            print("Invalid option. Please try again.")

    def send_to_daemon(self, message: str):
        """Sends a command to the daemon."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            client_socket.sendto(message.encode("ascii"), (self.daemon_ip, self.daemon_port))
    def receive_updates(self):
        """Receives updates from the daemon (incoming messages, chat requests)."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            client_socket.bind(("0.0.0.0", 7779))  # Dedicated port for daemon-to-client updates
            while self.running:
                try:
                    data, _ = client_socket.recvfrom(1024)
                    message = data.decode("ascii")
                    self.handle_daemon_message(message)
                except Exception as e:
                    print(f"Error receiving data: {e}")
    def handle_daemon_message(self, message: str):
        """Handles incoming messages or requests from the daemon."""
        if message.startswith("chat_request"):
            # Example message: "chat_request <IP> <username>"
            parts = message.split()
            remote_ip = parts[1]
            remote_user = parts[2]
            print(f"Incoming chat request from {remote_user} ({remote_ip}).")
            decision = input("Accept chat? (y/n): ").strip().lower()
            if decision == "y":
                self.send_to_daemon(f"accept {remote_ip}")
            else:
                self.send_to_daemon(f"reject {remote_ip}")
        elif message.startswith("chat_message"):
            # Example message: "chat_message <username>: <message>"
            print(message[12:])  # Display the message content
        elif message.startswith("chat_ended"):
            print("The chat has ended.")
    def send_chat_message(self):
        """Sends a chat message during an active chat."""
        while True:
            message = input("You: ").strip()
            if message.lower() == "quit":
                self.send_to_daemon("end_chat")
                break
            else:
                self.send_to_daemon(f"send {message}")

if __name__ == "__main__":
    daemon_ip = input("Enter the daemon's IP address: ").strip()
    client = Client(daemon_ip)
    client.start()




