import DNSServer

config = DNSServer.get_config()
SERVER_IPADDRESS = config["server_ip"]
SERVER_PORT = config["server_port"]

server = DNSServer.Server(SERVER_IPADDRESS, SERVER_PORT)
request = ''

while True:
    print('Waiting for incoming request...')
    data, full_client_address = server.receive_request()
    request = data.decode('utf-8')
    if request == 'exit':
        print('Closing connection.')
        break
    print(f'Received: \"{request}\" and answering.')
    answer = server.resolve(request.lower())
    server.send_answer(full_client_address, answer.encode())
    print()