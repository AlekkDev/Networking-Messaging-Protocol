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
            if data.decode() == "SYN":
                print(f"Received SYN from {client_address}")
                self.client_socket.sendto("SYN-ACK".encode(), client_address)

                # Step 3: Receive ACK
                data,_ = self.client_socket.recvfrom(1024)
                if data.decode() == "ACK":
                    print(f"Received ACK from {client_address}, handshake complete.")
                    print("Connection established")
                    break
    def listen_to_daemons(self):
        while True:
            data,daemon_address = self.daemon_socket.recvfrom(1024)
            print(f"Received message from daemon at{daemon_address}: {data.decode()}")




if __name__ == "__main__":
    daemon = SIMPDaemon("127.0.0.1", client_port=7778, daemon_port=7777)
    daemon.start()
