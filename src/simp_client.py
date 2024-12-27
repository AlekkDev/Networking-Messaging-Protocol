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
        self.socket.sendto("SYN".encode(), (self.daemon_ip, self.daemon_port))
        print("Sent SYN to daemon")

        #Step 2: Wait for SYN-ACK
        data,_ = self.socket.recvfrom(1024) # Receive SYN-ACK
        if data.decode() == "SYN-ACK":
            print("Received SYN-ACK from daemon")
            #Step 3: Send ACK
            self.socket.sendto("ACK".encode(), (self.daemon_ip, self.daemon_port))
            print("Sent ACK to daemon, handshake complete.")

if __name__ == "__main__":
    client = SIMPClient("127.0.0.1", 7778)
    client.connect()
