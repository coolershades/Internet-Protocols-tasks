import socket
import time
from SNTPPacket import Packet
import SNTPClient

NTP_PORT = 123
TIME1970 = 2208988800  # секунд прошло с 01.01.1900 до 01.01.1970


class Server:
    def __init__(self, self_ipaddress: str, port: int,  primary_time_server: str, delay=0):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self_ipaddress, port))

        self.client = SNTPClient.Client()  # клиент для отправки запроса в главный сервер
        self.client.socket.settimeout(5)

        self.reference_id = primary_time_server
        self.leap_indicator = 3
        self.precision = 0
        self.root_delay = 0
        self.reference_timestamp = None

        self.clock_offset = 0
        self.delay = delay

    def get_current_time(self):
        return time.time() - self.clock_offset + self.delay + TIME1970

    def synchronize(self):
        send_time = time.time()
        self.client.send_request((self.reference_id, NTP_PORT))
        clock_offset = SNTPClient.calculate_clock_offset(*self.client.receive_response())
        recv_time = time.time()
        self.root_delay = recv_time - send_time

        self.clock_offset += clock_offset
        self.reference_timestamp = self.get_current_time()
        self.leap_indicator = 0

    def generate_response(self, request_packet: Packet, receive_timestamp: float):
        response = Packet()

        response.version_number = request_packet.version_number
        response.mode = 4  # server
        response.stratum = 2
        response.poll = 4  # взяла значение из RFC
        response.precision = -6  # двоичная экспонента которого показывает точность системных часов
        response.root_delay = self.root_delay
        response.root_dispersion = 0  # максимальная ошибка из-за нестабильности часов (не умею такое измерять)
        response.reference_id = self.reference_id  # IP-адрес, с которым происходит сиинхронизцация (для вторичных серверов)

        response.reference_timestamp = self.reference_timestamp
        response.originate_timestamp = request_packet.transmit_timestamp
        response.receive_timestamp = receive_timestamp  # Время приёма запроса сервером

        return response

    def process_request(self):
        data, full_client_address = self.socket.recvfrom(512)

        receive_timestamp = self.get_current_time()
        request = Packet(data)
        if request.mode != 3:
            return

        response = self.generate_response(request, receive_timestamp)
        response.transmit_timestamp = self.get_current_time()  # время, в которое ответ покинул сервер

        self.socket.sendto(response.to_data(), full_client_address)
