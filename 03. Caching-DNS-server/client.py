from DNSClient import Client
import DNSServer

config = DNSServer.get_config()
FULL_SERVER_ADDRESS = (config["server_ip"], config["server_port"])

request = ''
client = Client(timeout=10)

while True:
    print('Type in resource record type and address to resolve:')
    request = input().strip()
    client.send_request(request.encode(), FULL_SERVER_ADDRESS)
    if request == 'exit':
        break
    answer_data, _ = client.receive_answer()
    print('Response: \"{}\"'.format(answer_data.decode().strip()))
    print()

client.close()
