import socket
import threading
import argparse

class SIMPDaemon:
    def __init__(self, client_port: int, daemon_port: int, ip: str):
        self.ip = ip
        self.client_port = client_port
        self.daemon_port = daemon_port
        self.client_address = None
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.bind((self.ip, self.client_port))
        self.daemon_socket.bind((self.ip, self.daemon_port))
        self.connections = {}
        self.sequence_number = 0
        print(f"Daemon listening on {self.ip}:{self.client_port} (client) and {self.ip}:{self.daemon_port} (daemon)...")

    def start(self):
        threading.Thread(target=self.listen_to_client, daemon=True).start()
        threading.Thread(target=self.listen_to_daemons, daemon=True).start()
        print("Daemon started, waiting for connections...")
        while True:
            pass

    def listen_to_client(self):
        while True:
            data, client_address = self.client_socket.recvfrom(1024)
            parsed_datagram = parse_datagram(data)
            if parsed_datagram["type"] == 0x01:  # Control datagrams
                if parsed_datagram["operation"] == 0x02:  # Connect request
                    self.handle_connect_request(parsed_datagram, client_address)
                elif parsed_datagram["operation"] == 0x03:  # Wait-for-connection request
                    self.handle_wait_request(parsed_datagram, client_address)
                elif parsed_datagram["operation"] == 0x05:  # Ping
                    self.handle_ping_request(parsed_datagram, client_address)

    def listen_to_daemons(self):
        while True:
            data, daemon_address = self.daemon_socket.recvfrom(1024)
            parsed_datagram = parse_datagram(data)
            if parsed_datagram["type"] == 0x01:  # Control datagrams
                if parsed_datagram["operation"] == 0x02:  # SYN
                    self.forward_to_client(parsed_datagram, daemon_address)
                elif parsed_datagram["operation"] == 0x06:  # SYN-ACK
                    self.forward_to_client(parsed_datagram, daemon_address)
                elif parsed_datagram["operation"] == 0x04:  # ACK
                    self.forward_to_client(parsed_datagram, daemon_address)

    def handle_connect_request(self, parsed_datagram, client_address):
        other_daemon_ip = parsed_datagram["payload"]
        user = parsed_datagram["user"]
        self.daemon_socket.sendto(create_datagram(0x01, 0x02, 0, user, self.ip), (other_daemon_ip, self.daemon_port)) # Forward SYN
        print(f"Sent connect request to daemon at {other_daemon_ip}")

    def handle_wait_request(self, parsed_datagram, client_address):
        print(f"Client {client_address} is waiting for connections [needs to be implemented]")



    def handle_ping_request(self, parsed_datagram, client_address):
        ping_response = create_datagram(0x01, 0x05, 0, "daemon", "pong")
        self.client_socket.sendto(ping_response, client_address)
        print(f"Ping response sent to {client_address}")

    def forward_to_client(self, parsed_datagram, daemon_address):
        self.client_socket.sendto(
            create_datagram(parsed_datagram["type"], parsed_datagram["operation"], parsed_datagram["sequence"],
                            parsed_datagram["user"]),
            (self.ip, self.client_port)
        )
        print(f"Forwarded operation {parsed_datagram['operation']} to client at {self.ip}")

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
    parser = argparse.ArgumentParser(description="SIMP Daemon")
    parser.add_argument("ip", type=str, help="IP address to bind to")
    args = parser.parse_args()

    daemon = SIMPDaemon(client_port=7778, daemon_port=7777, ip=args.ip)
    daemon.start()