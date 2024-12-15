import socket
import threading
import time


class Daemon:
    def __init__(self, ip_address: str):
        self.ip_address = ip_address
        self.daemon_port = 7777
        self.client_port = 7778
        self.buffer_size = 1024
    def start(self):
        threading.Thread(target=self.listen_to_others, daemon=True).start()
        threading.Thread(target=self.listen_to_client, daemon=True).start()

        while True:
            time.sleep(1)

    def listen_to_others(self):
        daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        daemon_socket.bind((self.ip_address, self.daemon_port))
        print(f"Listening for chats on {self.ip_address}:{self.daemon_port}")

        while True:
            try:
                data, addr = daemon_socket.recvfrom(self.buffer_size)
                print(f"Received data from {addr}: {data}")
                self.handle_daemon_message(data, addr, daemon_socket)
            except Exception as e:
                print(f"Error handling daemon message: {e}")

    def handle_daemon_message(self, data: bytes, addr: tuple, socket: socket.socket):
        # Parse the datagram
        datagram = self.parse_datagram(data)
        datagram_type = datagram["type"]
        operation = datagram["operation"]

        if datagram_type == 0x01:  # Control datagram
            if operation == 0x02:  # SYN
                self.handle_handshake(addr, datagram, socket)
            elif operation == 0x08:  # FIN
                self.handle_disconnect(addr, datagram)
        elif datagram_type == 0x02:  # Chat datagram
            self.forward_message_to_client(datagram["payload"])

    def listen_to_client(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while client_socket:
            client_socket.bind((self.ip_address, self.client_port))
            print(f"Listening for client on {self.ip_address}:{self.client_port}")

            while True:
                try:
                    data, addr = client_socket.recvfrom(self.buffer_size)
                    print(f"Received client data: {data}")
                    self.handle_client_message(data, addr, client_socket)
                except Exception as e:
                    print(f"Error handling client message: {e}")

    def handle_client_message(self, data: bytes, addr: tuple, socket: socket.socket):
        """Handles messages from the local client."""
        command = data.decode().strip()
        if command.startswith("connect"):
            self.initiate_chat_with_daemon(command, addr, socket)
        elif command.startswith("send"):
            self.send_chat_message(command, socket)
        elif command == "quit":
            self.cleanup_client(addr, socket)

    def parse_datagram(self, datagram: bytes) -> dict:
        """Parses the incoming datagram based on SIMP protocol."""
        return {
            "type": datagram[0],
            "operation": datagram[1],
            "sequence": datagram[2],
            "user": datagram[3:35].decode("ascii").strip(),
            "payload_length": int.from_bytes(datagram[35:39], byteorder="big"),
            "payload": datagram[39:].decode("ascii")
        }

    def create_datagram(self, datagram_type: int, operation: int, sequence: int, user: str, payload: str) -> bytes:
        """Constructs a SIMP datagram."""
        header = (
                datagram_type.to_bytes(1, "big") +
                operation.to_bytes(1, "big") +
                sequence.to_bytes(1, "big") +
                user.ljust(32).encode("ascii") +
                len(payload).to_bytes(4, "big")
        )
        return header + payload.encode("ascii")

    def handle_handshake(self, addr: tuple, datagram: dict, socket: socket.socket):
        """Handles the three-way handshake process."""
        print(f"Handshake initiated by {addr}.")
        response = self.create_datagram(0x01, 0x06, 0, "daemon", "")  # SYN+ACK
        socket.sendto(response, addr)


    def forward_message_to_client(self, message: str):
        """Forwards a chat message to the local client."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            client_socket.sendto(message.encode("ascii"), ("127.0.0.1", self.client_port))

if __name__ == "__main__":
    daemon_ip = "localhost"  # Replace with the IP address of your machine
    daemon = Daemon(daemon_ip)
    daemon.start()

