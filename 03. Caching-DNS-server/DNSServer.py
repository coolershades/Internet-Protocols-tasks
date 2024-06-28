import socket
import json
import ipaddr
import datetime
import re
from DNSPacket import Packet, create_request_packet, ip_to_ptr_address
from DNSClient import Client

# {
#   "a": {},
#   "aaaa": {},
#   "ns": {},
#   "ptr": {}
# }

type_to_str = {
    1: 'a',
    28: 'aaaa',
    2: 'ns',
    12: 'ptr'
}


def get_config():
    with open('config.json', 'r') as config_file:
        return json.load(config_file)


def ipv4_address_to_str(data: bytearray):
    return '{}.{}.{}.{}'.format(*list(data))


def ipv6_address_to_str(data: bytearray):
    return str(ipaddr.IPv6Address(ipaddr.Bytes(data)))


def marks_to_domain_name(marks: list):
    return '.'.join(marks)


transform_by_type = {
    'a': ipv4_address_to_str,
    'aaaa': ipv6_address_to_str,
    'ns': marks_to_domain_name,
    'ptr': marks_to_domain_name
}

IP_RE = re.compile("(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")


def is_ip_address(addr: str):
    match = IP_RE.match(addr)
    if not match:
        return False
    for i in range(1, 5):
        if int(match.group(i)) > 255:
            return False
    return True


def ip_is_gray(ip: str):
    ip_groups = re.search(IP_RE, ip)

    if ip_groups.group(1) == '10':
        return True
    if ip_groups.group(1) == '127':
        return True
    if ip_groups.group(1) == '192' and ip_groups.group(2) == '168':
        return True

    group2 = int(ip_groups.group(2))
    if ip_groups.group(1) == '172' and 16 <= group2 <= 31:
        return True

    return False


class Server:
    def __init__(self, self_ipaddress: str, self_port: int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self_ipaddress, self_port))
        config = get_config()
        self.next_server_full_address = (config['next_level_server'], config['next_level_server_port'])
        self.client = Client(timeout=5)
        with open('cache.json', 'r') as file:
            self.cache = json.load(file)

    def receive_request(self):
        data, full_address = self.socket.recvfrom(512)
        return data, full_address

    def send_answer(self, full_address, data):
        self.socket.sendto(data, full_address)

    def resolve(self, request: str):  # рекурсивно
        try:
            rr_type, address = request.split(' ')
        except ValueError:
            return 'Incorrect request!'

        if rr_type not in transform_by_type:
            return f'Can\'t process such question type: {rr_type}'
        if rr_type == 'ptr':
            if not is_ip_address(address):
                return 'Incorrect IP address!'
            if ip_is_gray(address):
                return 'Gray IP address.'
            address = ip_to_ptr_address(address)

        self.update_cache()
        response = ''
        cached_response = self.get_from_cache(rr_type, address)
        if cached_response:
            if 'answers' in cached_response:
                response += f'Unauthorized data: {", ".join(cached_response["answers"])}\n'

            if 'authority_records' in cached_response:
                response += f'Authority data: {", ".join(cached_response["authority_records"])}\n'

            if 'additional_records' in cached_response:
                response += f'Additional data: {", ".join(cached_response["additional_records"])}\n'
            return response
        else:
            try:
                response_packet = self.get_response_packet_by_type(address, rr_type)
            except socket.timeout:
                return 'Next-level server currently unavailable.'

            try:
                self.cache_packet(response_packet)
            except:
                return 'No such address!'

            transform = lambda a: transform_by_type[rr_type](a['r_data'])

            answers_data = list(map(transform, response_packet.answers))
            if len(answers_data) > 0:
                response += f'Unauthorized data: {", ".join(answers_data)}\n'

            authority_data = list(map(transform, response_packet.authority_records))
            if len(authority_data) > 0:
                response += f'Authority data: {", ".join(authority_data)}\n'

            additional_data = list(map(transform, response_packet.additional_records))
            if len(additional_data) > 0:
                response += f'Additional data: {", ".join(additional_data)}\n'

            return response

    def get_response_packet_by_type(self, address, rr_type: str):
        packet = create_request_packet(rr_type, address).collect_to_data()
        self.client.send_request(packet, self.next_server_full_address)
        response, _ = self.client.receive_answer()
        return Packet(response)

    def get_from_cache(self, request_type: str, address):
        result = {}
        is_cached = False
        for section in self.cache[request_type]:
            if address in self.cache[request_type][section]:
                is_cached = True
                data = []
                for record in self.cache[request_type][section][address]:
                    data.append(record['data'])
                result[section] = data

        if is_cached:
            print('Request is cached!')
            return result
        else:
            return None

    def cache_resource_record(self, resource_record, section: str):
        if resource_record['type'] not in type_to_str:
            raise Exception(f'Can\'t cache resource record of type: {resource_record["type"]}')
        rr_str_type = type_to_str[resource_record['type']]
        transform_rdata = transform_by_type[rr_str_type]
        if section not in self.cache[rr_str_type]:
            self.cache[rr_str_type][section] = {}
        save_to = self.cache[rr_str_type][section]
        domain_name = '.'.join(resource_record['name'])
        if domain_name not in save_to:
            save_to[domain_name] = []
        save_to[domain_name].append({
            'data': transform_rdata(resource_record['r_data']),
            'ttl': resource_record['ttl'],
            'caching_datetime': str(datetime.datetime.now())
        })

    def cache_packet(self, packet: Packet):
        for answer in packet.answers:
            self.cache_resource_record(answer, 'answers')
        for auth_r in packet.authority_records:
            self.cache_resource_record(auth_r, 'authority_records')
        for add_r in packet.additional_records:
            self.cache_resource_record(add_r, 'additional_records')
        self.save_cache()

    def save_cache(self):
        with open('cache.json', 'w') as file:
            json.dump(self.cache, file)

    def update_cache(self):
        for rr_type in self.cache:
            for section in self.cache[rr_type]:
                for address in self.cache[rr_type][section]:
                    for record in self.cache[rr_type][section][address]:
                        caching_datetime = datetime.datetime.strptime(record['caching_datetime'],
                                                                      '%Y-%m-%d %H:%M:%S.%f')
                        if (datetime.datetime.now() - caching_datetime).total_seconds() > record['ttl']:
                            records = self.cache[rr_type][section][address]
                            del records[records.index(record)]
