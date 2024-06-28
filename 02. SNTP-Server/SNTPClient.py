import time
import socket
from SNTPPacket import Packet

TIME1970 = 2208988800  # секунд прошло с 01.01.1900 до 01.01.1970


def generate_request():
    packet = Packet()
    packet.mode = 3  # client
    return packet


def calculate_roundtrip_delay(response: Packet, destination_timestamp: float):
    return (destination_timestamp - response.originate_timestamp) - \
           (response.transmit_timestamp - response.receive_timestamp)


def calculate_clock_offset(response: Packet, destination_timestamp: float):
    return ((response.receive_timestamp - response.originate_timestamp) +
            (response.transmit_timestamp - destination_timestamp)) / 2


class Client:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(5)
        self.clock_offset = 0

    def get_current_time(self):
        return time.time() + self.clock_offset + TIME1970

    def send_request(self, full_server_addr):
        request_packet = generate_request()
        request_packet.transmit_timestamp = self.get_current_time()
        self.socket.sendto(request_packet.to_data(), full_server_addr)

    def receive_response(self):
        data = self.socket.recv(512)
        destination_timestamp = self.get_current_time()
        return Packet(data), destination_timestamp

    def synchronize(self, timeserver_full_address):
        self.send_request(timeserver_full_address)
        response, destination_timestamp = self.receive_response()
        self.clock_offset += calculate_clock_offset(response, destination_timestamp)

    def shutdown(self):
        self.socket.close()
