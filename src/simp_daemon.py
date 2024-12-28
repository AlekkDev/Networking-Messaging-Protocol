import socket
import threading
class SIMPDaemon:
    # Constructor
    def __init__(self, ip: str,client_port:int, daemon_port: int): #
        self.ip = ip
        self.client_port = client_port
        self.daemon_port = daemon_port

        # Create two UDP sockets, for client and daemon
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind each socket to its respective port
        self.client_socket.bind((self.ip, self.client_port))
        self.daemon_socket.bind((self.ip, self.daemon_port))

        print(f"Daemon listening on {self.ip}:{self.client_port} (client) and {self.ip}:{self.daemon_port} (daemon)...")

    def start(self):
        # Create threads for listening on each port
        threading.Thread(target=self.listen_to_client, daemon=True).start()
        threading.Thread(target=self.listen_to_daemons, daemon=True).start()


        # Keep the main thread alive
        print("Daemon started, waiting for connections...")
        while True:
            pass

    def listen_to_client(self):
        while True:
            data,client_address = self.client_socket.recvfrom(1024)
            # Step 1: Receive SYN
            syn_datagram = parse_datagram(data)
            if syn_datagram["type"] == 0x01 and syn_datagram["operation"] == 0x02:
                print(f"Received SYN from {client_address}")
                # Step 2: Send SYN-ACK
                syn_ack_datagram = create_datagram(0x01, 0x06, 0, "daemon")
                self.client_socket.sendto(syn_ack_datagram, client_address)

                # Step 3: Receive ACK
                data,_ = self.client_socket.recvfrom(1024)
                parsed_datagram = parse_datagram(data)
                if parse_datagram(data)["type"] == 0x01 and parse_datagram(data)["operation"] == 0x04:
                    print(f"Received ACK from {client_address}, handshake complete.")
                    print("Connection established")
                    break
    def listen_to_daemons(self):
        while True:
            data,daemon_address = self.daemon_socket.recvfrom(1024)
            print(f"Received message from daemon at{daemon_address}: {data.decode()}")


# Datagram functions
    # Create datagram
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

    # Parse datagram
def parse_datagram(data: bytes) -> dict:
    # Parse the datagram into its components
    datagram_type = data[0]
    operation = data[1]
    sequence = data[2]
    user = data[3:35].decode('ascii').strip() #strip removes leading and trailing whitespaces
    payload_length = int.from_bytes(data[35:39], 'big')
    # Extract the payload
    payload = data[39:39 + payload_length].decode('ascii')
    # Return the parsed datagram as a dictionary
    return {
        "type": datagram_type,
        "operation": operation,
        "sequence": sequence,
        "user": user,
        "payload_length": payload_length,
        "payload": payload
    }

if __name__ == "__main__":
    daemon = SIMPDaemon("127.0.0.1", client_port=7778, daemon_port=7777)
    daemon.start()
