import struct
import re


def format_to_time(seconds: int, fraction: int):
    return seconds + float(fraction) / (2 ** 32)


def time_to_format(timestamp: float):
    seconds = int(timestamp)
    fraction = int((timestamp - seconds) * (2 ** 32))
    return seconds, fraction


ipv4_pattern = re.compile(r'([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)')


def format_reference(stratum: int, reference_id: str):
    if stratum <= 1 and len(reference_id) <= 4:
        return int.from_bytes(bytes(reference_id, 'ascii'), 'big')
    else:
        match = re.match(ipv4_pattern, reference_id)
        if match:
            return int.from_bytes(struct.pack('! 4B', *map(lambda x: int(x), match.groups())), 'big')
        else:
            raise Exception('Incorrect reference ID.')


class Packet:
    FORMAT = '!B B B b 11I'

    def __init__(self, data=None):
        self.leap_indicator = 0
        self.version_number = 4
        self.mode = 0
        self.stratum = 0
        self.poll = 0
        self.precision = 0
        self.root_delay = 0
        self.root_dispersion = 0
        self.reference_id = ''
        self.reference_timestamp = 0.0
        self.originate_timestamp = 0.0
        self.receive_timestamp = 0.0
        self.transmit_timestamp = 0.0
        # опционально, в пакет класть не будем
        self.key_id = None
        self.message_digest = None

        if data:
            self.rewrite_from_data(data)

    def rewrite_from_data(self, data):
        try:
            unpacked = struct.unpack(Packet.FORMAT, data[0:struct.calcsize(Packet.FORMAT)])
        except struct.error:
            raise Exception("Unable to unpack data.")

        self.leap_indicator = unpacked[0] >> 6  # строка 1
        self.version_number = unpacked[0] >> 3 & 0x7
        self.mode = unpacked[0] & 0x7
        self.stratum = unpacked[1]
        self.poll = unpacked[2]
        self.precision = unpacked[3]
        self.root_delay = float(unpacked[4]) / (2 ** 16)  # строка 2, знаковое
        self.root_dispersion = float(unpacked[5]) / (2 ** 16)  # с   трока 3, БЕЗЗНАКОВОЕ
        # self.reference_id = unpacked[6]  # IP-адрес для вторичных серверов, 4 байта подряд
        self.reference_id = '.'.join(map(lambda x: str(x), data[12:12+4]))
        self.reference_timestamp = format_to_time(unpacked[7], unpacked[
            8])  # когда системные часы последний раз были установлены или скорректированны
        self.originate_timestamp = format_to_time(unpacked[9],
                                                  unpacked[10])  # Время отправки запроса клиентом, несинхрониз.
        self.receive_timestamp = format_to_time(unpacked[11], unpacked[12])  # Время приёма запроса сервером
        self.transmit_timestamp = format_to_time(unpacked[13], unpacked[
            14])  # время, в кот. запрос покинул клиента, или ответ покинул сервер

    def to_data(self):
        li_vn_mode = (self.leap_indicator << 6 | self.version_number << 3 | self.mode)
        root_delay = int(self.root_delay * (2 ** 16))
        root_dispersion = int(self.root_dispersion * (2 ** 16))
        reference_id = format_reference(self.stratum, self.reference_id)
        reference_timestamp_sec, reference_timestamp_frac = time_to_format(self.reference_timestamp)
        originate_timestamp_sec, originate_timestamp_frac = time_to_format(self.originate_timestamp)
        receive_timestamp_sec, receive_timestamp_frac = time_to_format(self.receive_timestamp)
        transmit_timestamp_sec, transmit_timestamp_frac = time_to_format(self.transmit_timestamp)

        try:
            packed = struct.pack(Packet.FORMAT,
                                 li_vn_mode,
                                 self.stratum,
                                 self.poll,
                                 self.precision,
                                 root_delay,
                                 root_dispersion,
                                 reference_id,
                                 reference_timestamp_sec, reference_timestamp_frac,
                                 originate_timestamp_sec, originate_timestamp_frac,
                                 receive_timestamp_sec, receive_timestamp_frac,
                                 transmit_timestamp_sec, transmit_timestamp_frac)
        except struct.error:
            raise Exception('Invalid data for SNTP packet fields.')
        return packed

    def __str__(self):
        return '''Leap indicator:\t\t{}
Version number:\t\t{}
Mode:\t\t\t{}
Stratum:\t\t{}
Poll:\t\t\t{}
Precision:\t\t{}
Root delay:\t\t{}
Root dispersion:\t{}
Reference ID:\t\t{}
Reference timestamp:\t{}
Originate timestamp:\t{}
Receive timestamp:\t{}
Transmit timestamp:\t{}
        '''.format(self.leap_indicator,
                   self.version_number,
                   self.mode,
                   self.stratum,
                   self.poll,
                   self.precision,
                   self.root_delay,
                   self.root_dispersion,
                   self.reference_id,
                   self.reference_timestamp,
                   self.originate_timestamp,
                   self.receive_timestamp,
                   self.transmit_timestamp)
