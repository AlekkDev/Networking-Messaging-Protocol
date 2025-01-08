import socket
import threading
import argparse
class SIMPDaemon:
    # Constructor
    def __init__(self,client_port:int, daemon_port: int, ip: str):
        self.ip = ip
        self.client_port = client_port
        self.daemon_port = daemon_port
        self.connected_clients = {}
        

        # Create two UDP sockets, for client and daemon
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.daemon_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind each socket to its respective port
        self.client_socket.bind((self.ip, self.client_port))
        self.daemon_socket.bind((self.ip, self.daemon_port))

        # Track active sessions
        self.active_sessions = {}
        self.sequence_number = 0 # Expected seq.number for stop-and-wait retransmission

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
            data, client_address = self.client_socket.recvfrom(1024)
            parsed_datagram = parse_datagram(data)

            # Handle datagram based on type and operation
            if parsed_datagram["type"] == 0x01:  # Control datagrams
                if parsed_datagram["operation"] == 0x02:  # SYN
                    self.handle_syn(client_address)
                elif parsed_datagram["operation"] == 0x08:  # FIN
                    self.handle_fin(client_address)

                elif parsed_datagram["operation"] == 0x01:  # Chat initiation request
                    self.handle_chat_request(parsed_datagram, client_address)

            elif parsed_datagram["type"] == 0x02 and parsed_datagram["operation"] == 0x01:  # Chat message
                self.handle_chat_message(parsed_datagram, client_address)

    def handle_syn(self, client_address): # 3-way handshake
        print(f"Received SYN from {client_address}")

        # STEP 2: Send SYN-ACK
        syn_ack_datagram = create_datagram(0x01, 0x06, 0, "daemon")
        self.client_socket.sendto(syn_ack_datagram, client_address)

        # STEP 3: Receive ACK
        data, _ = self.client_socket.recvfrom(1024)
        parsed_datagram = parse_datagram(data)
        if parsed_datagram["type"] == 0x01 and parsed_datagram["operation"] == 0x04:
            print(f"Received ACK from {client_address}, handshake complete.")
            print("Connection established")
            self.active_sessions[client_address] = True

            #add all the clients that connect to daemon to a list where you can see all available clients that are ready to chat
            username = parse_datagram["user"]
            self.connected_clients[client_address] = {"username" : username}
            print(self.connected_clients)
        

    def handle_fin(self, client_address):
        print(f"Received FIN from {client_address}")
        # Acknowledge the termination
        fin_ack_datagram = create_datagram(0x01, 0x04, 0, "daemon")
        self.client_socket.sendto(fin_ack_datagram, client_address)
        # Close the session
        print(f"Session with {client_address} terminated.")
        if client_address in self.active_sessions:
            del self.active_sessions[client_address]


    def handle_chat_request(self, parsed_datagram, client_address):
        target_client_ip = parsed_datagram["payload"]
        print(f"Received chat request from client 1 {client_address} to client 2 {target_client_ip}")

        daemon2_ip = "127.0.0.2"
        daemon2_port = 7777

        forwarded_datagram = create_datagram(
            parsed_datagram["type"],
            parsed_datagram["operation"],
            parsed_datagram["sequence"],
            parsed_datagram["user"],
            parsed_datagram["payload"]
        )

        self.daemon_socket.sendto(forwarded_datagram, (daemon2_ip, daemon2_port))


    def handle_chat_message(self, parsed_datagram, client_address):
        """Handle chat messages and send acknowledgments."""
        if parsed_datagram["sequence"] == self.sequence_number:
            print(f"Received message from {client_address}: {parsed_datagram['payload']}")

            # Send acknowledgment
            ack_datagram = create_datagram(0x01, 0x04, parsed_datagram["sequence"], "daemon")
            self.client_socket.sendto(ack_datagram, client_address)
            print("Acknowledgment sent.")

            # Toggle expected sequence number
            self.sequence_number ^= 1
        else:
            print(f"Duplicate message received from {client_address}. Ignoring...")


    def listen_to_daemons(self):
        while True:
            data,daemon_address = self.daemon_socket.recvfrom(1024)
            parsed_datagram = parse_datagram(data)
            print(f"Received message from daemon at{daemon_address}: {parsed_datagram}")

            # Forward the message to Client 2 if it is a chat initiation request
            if parsed_datagram["operation"] == 0x01:  # Chat initiation request
                target_client_ip = parsed_datagram["payload"]
                print(f"Forwarding chat request to client 2 {target_client_ip}")

                # Forward the request to Client 2


                forwarded_datagram = create_datagram(
                    parsed_datagram["type"],
                    parsed_datagram["operation"],
                    parsed_datagram["sequence"],
                    parsed_datagram["user"],
                    parsed_datagram["payload"]
                    )
                
                try:
                    print(f"Sending message to {target_client_ip}:{self.client_port}")
                    self.client_socket.sendto(forwarded_datagram, (target_client_ip, self.client_port))
                    print("Message forwarded to Client 2.")
                except Exception as e:
                    print(f"Error sending message to Client 2: {e}")

                print("Before the listen client")
                self.listen_to_client_response(target_client_ip)
                print("Tried to forward to client 2")

    def listen_to_client_response(self, target_client_ip):
        while True:
            data, client_address = self.client_socket.recvfrom(1024)

            print(f"Received data from {client_address}: {data}")

            if client_address[0] != target_client_ip:
                print(f"Skipping message from {client_address}, expected {target_client_ip}")
                continue

            parsed_datagram = parse_datagram(data)
            print(f"Received response from client 2: {parsed_datagram['payload']}")

            daemon1_ip = "127.0.0.1"
            daemon1_port = 7777
            try:
                self.client_socket.sendto(parsed_datagram, (daemon1_ip, daemon1_port))
                print(f"Response forwarded to Daemon 1: {parsed_datagram}")
            except Exception as e:
                print(f"Error sending response to Daemon 1: {e}")





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
    parser = argparse.ArgumentParser(description="SIMP Daemon")
    parser.add_argument("ip", type=str, help="IP address to bind to")
    args = parser.parse_args()

    daemon = SIMPDaemon(client_port=7778, daemon_port=7777, ip=args.ip)
    daemon.start()
