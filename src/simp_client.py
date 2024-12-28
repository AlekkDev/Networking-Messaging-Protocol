import socket

class SIMPClient:
    def __init__(self, daemon_ip: str, daemon_port: int):
        self.daemon_ip = daemon_ip
        self.daemon_port = daemon_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print(f"Client created, ready to connect to daemon at {self.daemon_ip}:{self.daemon_port}")
    def connect(self):
        """Initiate the 3-way handshake"""
        #Step 1: Send SYN
        # Create a SYN datagram
        syn_datagram = create_datagram(0x01, 0x02, 0, "client1")
        self.socket.sendto(syn_datagram, (self.daemon_ip, self.daemon_port))
        print("Sent SYN to daemon")

        #Step 2: Wait for SYN-ACK
        data,_ = self.socket.recvfrom(1024) # Receive SYN-ACK
        parsed_datagram = parse_datagram(data)
        if parsed_datagram["type"] == 0x01 and parsed_datagram["operation"] == 0x06: # Check received is SYN-ACK
            print("Received SYN-ACK from daemon")
            #Step 3: Send ACK
            ack_datagram = create_datagram(0x01, 0x04, 0, "client1")
            self.socket.sendto("ACK".encode(), (self.daemon_ip, self.daemon_port))
            print("Sent ACK to daemon, handshake complete.")


# Datagram functions
def create_datagram(datagram_type: int, operation: int, sequence: int, user: str, payload: str = "") -> bytes:
    """
    Creates a SIMP datagram with the specified fields.

    Args:
        datagram_type (int): The type of the datagram (e.g., 0x01 for control, 0x02 for chat).
        operation (int): The specific operation (e.g., SYN, ACK).
        sequence (int): The sequence number (0 or 1).
        user (str): The username (max 32 characters).

        payload (str): The payload content.

    Returns:
        bytes: The packed datagram as a byte string.
    """
    # Ensure username is exactly 32 bytes (padded or truncated)
    user_field = user.ljust(32)[:32].encode('ascii')

    # Calculate payload length (also included in header)
    payload_length = len(payload)

    # Header fields
    header = (
            datagram_type.to_bytes(1, 'big') +
            operation.to_bytes(1, 'big') +
            sequence.to_bytes(1, 'big') +
            user_field +
            payload_length.to_bytes(4, 'big')
    )

    # Combine header and payload
    return header + payload.encode('ascii')
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
    client = SIMPClient("127.0.0.1", 7778)
    client.connect()
