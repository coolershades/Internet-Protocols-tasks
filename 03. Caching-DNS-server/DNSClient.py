import socket


class Client:
    def __init__(self, timeout: int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(timeout)

    def send_request(self, data: bytes, full_server_addr: tuple):
        self.socket.sendto(data, full_server_addr)

    def receive_answer(self):
        data, full_server_address = self.socket.recvfrom(1024)
        return data, full_server_address

    def close(self):
        self.socket.close()
