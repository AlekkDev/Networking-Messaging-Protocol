import socket
import threading
import argparse

class SIMPDaemon:
    def __init__(self, client_port: int, daemon_port: int, daemon_ip: str):
        self.daemon_ip = daemon_ip
        self.client_port = client_port  # 7778
        self.daemon_port = daemon_port  # 7777
        self.client_address = None
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.bind((self.daemon_ip, self.client_port))
        self.daemon_socket.bind((self.daemon_ip, self.daemon_port))
        self.connected_client = None
        self.connected_daemon = None
        print(f"Daemon listening on {self.daemon_ip}:{self.client_port} (client) and {self.daemon_ip}:{self.daemon_port} (daemon)...")


    # Start the daemon, listening for incoming connections on both ports
    def start(self):
        threading.Thread(target=self.listen_to_client, daemon=True).start()
        threading.Thread(target=self.listen_to_daemons, daemon=True).start()
        print("Daemon started, waiting for connections...")
        while True:
            pass
    # Listen to incoming connections from client port
    def listen_to_client(self):
        while True:
            data, client_address = self.client_socket.recvfrom(1024)
            parsed_datagram = parse_datagram(data)
            if parsed_datagram["type"] == 0x01:  # Control datagrams
                if parsed_datagram["operation"] == 0x02:  # Connect request
                    self.handle_client_connection(parsed_datagram, client_address)
                elif parsed_datagram["operation"] == 0x05:  # Ping
                    self.handle_ping_request(client_address)


    # Listen to incoming connections from daemon port
    def listen_to_daemons(self):
        while True:
            data, daemon_address = self.daemon_socket.recvfrom(1024)
            parsed_datagram = parse_datagram(data)
            if parsed_datagram["type"] == 0x01:  # Control datagrams
                if parsed_datagram["operation"] == 0x02:  # Receive SYN
                    self.handle_daemon_connect_request(parsed_datagram, daemon_address)

    # Handle connect request from a daemon
    def handle_client_connection(self, parsed_datagram,client_address):
        # If no client is connected, accept the connection
        if self.connected_client is None:
            self.client_address = client_address
            # STEP 2: Send SYN-ACK to client
            syn_ack_datagram = create_datagram(0x01, 0x06, 0, "daemon")
            self.client_socket.sendto(syn_ack_datagram, client_address)
            # STEP 3: Receive ACK from client
            data, _ = self.client_socket.recvfrom(1024)
            parsed = parse_datagram(data)
            if parsed["type"] == 0x01 and parsed["operation"] == 0x04:  # ACK
                self.connected_client = client_address
            print(f"Connected to client: {client_address}")
        else:
            fin_datagram = create_datagram(0x01, 0x04, 0, "client", "Connection rejected")
            self.client_socket.sendto(fin_datagram, client_address)
            print(f"Rejected connection from {client_address} (FIN)")



    def handle_daemon_connect_request(self, parsed_datagram, daemon_address):
        if self.connected_daemon is None:
            self.connected_daemon = daemon_address
            print(f"Connected to daemon: {daemon_address}")
        else:
            fin_datagram = create_datagram(0x01, 0x04, 0, "daemon", "Connection rejected")
            self.daemon_socket.sendto(fin_datagram, daemon_address)
            print(f"Rejected connection from {daemon_address} (FIN)")

    # Handle wait-for-connection request from a client
    def handle_wait_request(self, parsed_datagram, client_address):

        username = parsed_datagram["user"]
        if len(self.connections) != 0:
            print(f"Another client is already waiting: {self.connections}. Rejecting new request.")

            return
        self.waiting_client = (client_address, username)
        print(f"Client {client_address} ({username}) is now waiting for connections.")

    # Used to ping back the client
    def handle_ping_request(self, client_address):
        ping_response = create_datagram(0x01, 0x05, 0, "daemon", "pong")
        self.client_socket.sendto(ping_response, client_address)
        print(f"Ping response sent to {client_address}")

    def forward_to_client(self, parsed_datagram, daemon_address):
        client_datagram = create_datagram(parsed_datagram["type"], parsed_datagram["operation"], parsed_datagram["sequence"],
                            parsed_datagram["user"], parsed_datagram["payload"])
        self.client_socket.sendto(client_datagram, (self.ip, self.client_port))
        print(f"Forwarded operation {parsed_datagram['operation']} to client at {self.ip, self.client_port}")

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
    parser.add_argument("daemon_ip", type=str, help="Daemon IP address")
    args = parser.parse_args()

    daemon = SIMPDaemon(client_port=7778, daemon_port=7777, daemon_ip=args.daemon_ip)
    daemon.start()