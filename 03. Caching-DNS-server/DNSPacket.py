import struct
import random
import re

HEADER_FORMAT = '! 6H '


# pointer - отсчёт слева направо, с нуля
def get_bits(source: int, pointer: int, length=1):
    return (source >> ((pointer - length) + 1)) & ((1 << length) - 1)


def join_bytes(arr: bytearray):
    result = 0
    for i in range(len(arr)):
        result = (result << 8) + arr[i]
    return result


def read_mark(packet: bytearray, position: int, length: int):
    return packet[position + 1:position + length + 1], position + length + 1


def disassemble_first_mark_byte(packet: bytearray, position: int):
    indicator = get_bits(packet[position], 7, 2)
    tail = get_bits(packet[position], 5, 6)
    return indicator, tail


def decode_marks(packet: bytearray, start_position: int):  # в С.О. с нуля
    current_mark_pointer = start_position
    current_byte_pointer = start_position
    marks = []
    while packet[current_mark_pointer] != 0:
        indicator, tail = disassemble_first_mark_byte(packet, current_byte_pointer)
        if indicator == 0:
            mark, current_mark_pointer = read_mark(packet, current_byte_pointer, tail)
            current_byte_pointer = current_mark_pointer
            marks.append(mark.decode('ascii'))
            if packet[current_mark_pointer] == 0:
                current_byte_pointer += 1  # в расчете на завершающий нулевой байт
        elif indicator == 3:
            link = (tail << 8) + packet[current_byte_pointer + 1]  # в отсчёте с нуля
            linked_marks, current_mark_pointer = decode_marks(packet, link)
            marks += linked_marks
            current_byte_pointer += 2
        else:
            raise Exception('There can\'t be such a mark')
        if current_byte_pointer >= len(packet):
            break
    return marks, current_byte_pointer


def decode_resource_record(packet: bytearray, start_position: int):
    marks, current_pointer = decode_marks(packet, start_position)
    r_type = join_bytes(packet[current_pointer:current_pointer + 2])
    current_pointer += 2
    r_class = join_bytes(packet[current_pointer:current_pointer + 2])
    current_pointer += 2
    r_ttl = join_bytes(packet[current_pointer:current_pointer + 4])
    current_pointer += 4
    r_data_length = join_bytes(packet[current_pointer:current_pointer + 2])
    current_pointer += 2
    r_data = packet[current_pointer:current_pointer + r_data_length]

    if r_type == 2 or r_type == 12:  # 2 = NS, 12 = PTR
        r_data, _ = decode_marks(packet, current_pointer)
    current_pointer += r_data_length

    data = {
        'name': marks,
        'type': r_type,
        'class': r_class,
        'ttl': r_ttl,
        'rd_length': r_data_length,
        'r_data': r_data
    }

    return data, current_pointer


def question_to_data(question: dict, ngrams_used: dict, bytes_previously_written: int):
    question_data = marks_to_data(question['q_marks'], ngrams_used, bytes_previously_written)
    question_data += (int.to_bytes(question['q_type'], 2, 'big') +
                      int.to_bytes(question['q_class'], 2, 'big'))
    return question_data


def resource_record_to_data(rr: dict, ngrams_used: dict, bytes_previously_written: int):
    rr_data = marks_to_data(rr['name'], ngrams_used, bytes_previously_written)
    rr_data += int.to_bytes(rr['type'], 2, 'big')
    rr_data += int.to_bytes(rr['class'], 2, 'big')
    rr_data += int.to_bytes(rr['ttl'], 4, 'big')
    rr_data += int.to_bytes(rr['rd_length'], 2, 'big')

    if str(type(rr['r_data'])) == '<class \'list\'>':
        rr_data += marks_to_data(rr['r_data'], ngrams_used, bytes_previously_written + len(rr_data))
    else:
        rr_data += rr['r_data']

    return rr_data


def marks_to_data(marks: list, ngrams_used: dict, bytes_previously_written: int):
    result = b''
    position = bytes_previously_written
    for i in range(len(marks)):
        str_ngram = '.'.join(marks[i:])
        if str_ngram in ngrams_used:
            link = ngrams_used[str_ngram]
            data = (int.to_bytes((3 << 6) + get_bits(link, 13, 6), 1, 'big') +
                    int.to_bytes(get_bits(link, 7, 8), 1, 'big'))
            result += data
            position += len(data)
            break
        else:
            ngrams_used[str_ngram] = position
            mark = marks[i]
            data = int.to_bytes(len(mark), 1, 'big') + mark.encode()
            result += data
            position += len(data)
            if i == len(marks) - 1:  # если последняя марка была использована впервые, то...
                result += int.to_bytes(0, 1, 'big')  # добавить окончающий байт
    return result


def ip_to_ptr_address(ip: str):
    return '.'.join(list(reversed(ip.split('.'))) + ['in-addr', 'arpa'])


def create_request_packet(rr_type, address):
    packet = Packet()
    packet.id = random.randint(0, 65535)
    packet.qr = 0
    packet.opcode = 0
    packet.rd = 1
    packet.qd_count = 1
    marks = address.split('.')

    if rr_type == 'a':
        q_type = 1
    elif rr_type == 'aaaa':
        q_type = 28
    elif rr_type == 'ns':
        q_type = 2
    elif rr_type == 'ptr':
        q_type = 12
    else:
        raise Exception(f'Can\'t create a request packet of type: {rr_type}')

    packet.questions = [{
        'q_marks': marks,
        'q_type': q_type,
        'q_class': 1  # INternet
    }]

    return packet


class Packet:
    def __init__(self, data=None):
        # ---- HEADER ----
        self.id = 0
        self.qr = 0  # question or response
        self.opcode = 0  # тип запроса
        self.aa = 0  # authoritative answer
        self.tc = 0  # trimmed content
        self.rd = 0  # recursion desired
        self.ra = 0  # recursion allowed
        self.z = 0  # Zарезервировано
        self.rcode = 0  # response code

        self.qd_count = 0  # кол-во question записей
        self.an_count = 0  # кол-во записей ответов
        self.ns_count = 0  # количество записей в Authority Section
        self.ar_count = 0  # количество записей в Additional Record Section
        # ----------------

        self.questions = []
        self.answers = []
        self.authority_records = []
        self.additional_records = []

        if data:
            self.rewrite_from_data(data)

    def __str__(self):
        return f'''--------------------------------
Packet ID:\t{self.id}

Question/Response:\t{self.qr}
Operation Code:\t\t{self.opcode}
Authoritative Answer:\t{self.aa}
Trimmed Content:\t{self.tc}
Recursion Desired:\t{self.rd}
Recursion Allowed:\t{self.ra}
Z (reserved):\t{self.z}
Response Code:\t{self.rcode}

QD (questions count):\t{self.qd_count}
AN (answers count):\t{self.an_count}
NS (authority section records count):\t{self.ns_count}
AR (additional records count):\t{self.ar_count} 

Questions:
{self.questions}

Answers:
{self.answers}

Authority Records:
{self.authority_records}

Additional Records:
{self.additional_records}
--------------------------------'''

    def rewrite_header_from_data(self, header_data: bytes):
        try:
            unpacked = struct.unpack(HEADER_FORMAT, header_data[0:struct.calcsize(HEADER_FORMAT)])
        except struct.error:
            raise Exception('Unable to unpack data.')

        self.id = unpacked[0]

        self.qr = get_bits(unpacked[1], 15, 1)
        self.opcode = get_bits(unpacked[1], 14, 4)
        self.aa = get_bits(unpacked[1], 10, 1)
        self.tc = get_bits(unpacked[1], 9, 1)
        self.rd = get_bits(unpacked[1], 8, 1)
        self.ra = get_bits(unpacked[1], 7, 1)
        self.z = get_bits(unpacked[1], 6, 3)
        self.rcode = get_bits(unpacked[1], 3, 4)

        self.qd_count = unpacked[2]
        self.an_count = unpacked[3]
        self.ns_count = unpacked[4]
        self.ar_count = unpacked[5]

    def header_to_data(self):
        second_row = ((self.qr << 15) + (self.opcode << 11) + (self.aa << 10) + (self.tc << 9) + (self.rd << 8) +
                      (self.ra << 7) + self.rcode)
        try:
            header = struct.pack(HEADER_FORMAT,
                                 self.id,
                                 second_row,
                                 self.qd_count,
                                 self.an_count,
                                 self.ns_count,
                                 self.ar_count)
        except struct.error:
            raise Exception('Invalid data for DNS header packet fields.')
        return header

    def rewrite_from_data(self, data: bytes):
        if len(data) < 12:
            raise Exception('Data not long enough to unpack.')

        packet = bytearray(data)
        self.rewrite_header_from_data(bytes(packet[0:12]))
        next_pointer = 12

        questions = []
        for i in range(self.qd_count):
            q_marks, next_pointer = decode_marks(packet, next_pointer)
            q_type = join_bytes(packet[next_pointer:next_pointer + 2])
            q_class = join_bytes(packet[next_pointer + 2:next_pointer + 4])
            next_pointer += 4

            question = {
                'q_marks': q_marks,
                'q_type': q_type,
                'q_class': q_class
            }
            questions.append(question)
        self.questions = questions

        answers = []
        for i in range(self.an_count):
            answer, next_pointer = decode_resource_record(packet, next_pointer)
            answers.append(answer)
        self.answers = answers

        authority_records = []
        for i in range(self.ns_count):
            auth_rec, next_pointer = decode_resource_record(packet, next_pointer)
            authority_records.append(auth_rec)
        self.authority_records = authority_records

        additional_records = []
        for i in range(self.ar_count):
            add_rec, next_pointer = decode_resource_record(packet, next_pointer)
            additional_records.append(add_rec)
        self.additional_records = additional_records

    def collect_to_data(self):
        packet_data = self.header_to_data()
        ngrams_used = {}  # словарь str -> int (position)

        for question in self.questions:
            packet_data += question_to_data(question, ngrams_used, len(packet_data))

        for answer in self.answers:
            packet_data += resource_record_to_data(answer, ngrams_used, len(packet_data))

        for auth_rec in self.authority_records:
            packet_data += resource_record_to_data(auth_rec, ngrams_used, len(packet_data))

        for add_rec in self.additional_records:
            packet_data += resource_record_to_data(add_rec, ngrams_used, len(packet_data))

        return packet_data
