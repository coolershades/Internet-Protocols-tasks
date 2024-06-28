import socket
import ssl
import json


HOST_ADDR = 'api.vk.com'
PORT = 443  # HTTPS
CURRENT_VK_VERSION = 5.199

with open('config.json', 'r') as file:
    config_data = json.load(file)
    access_token = config_data['access_token']


def receive(sock):
    result = b''
    response = sock.recv()
    while len(response) > 0:
        result += response
        try:
            json.loads(result.decode().split('\r\n\r\n')[-1])
            break
        except UnicodeDecodeError:
            response = sock.recv()
        except json.decoder.JSONDecodeError:
            response = sock.recv()
    return result.decode()


def format_params(params_dict):
    all_params = []
    for param in params_dict:
        all_params.append(f'{param}={params_dict[param]}')
    return '&'.join(all_params)


def get_friends(sock, user_id):
    method = 'friends.get'
    params = {
        'user_id': user_id,
        'access_token': config_data['access_token'],
        'v': CURRENT_VK_VERSION
    }

    request = f'GET https://{HOST_ADDR}/method/{method}?{format_params(params)} HTTP/1.1\n'
    request += f'Host: {HOST_ADDR}\n'
    request += '\n'

    sock.send(request.encode())
    response = receive(sock)
    response_body = response.split('\r\n\r\n')[-1]

    friends_ids = json.loads(response_body)['response']['items']
    return get_full_names(sock, friends_ids)


def get_full_names(sock, user_ids):
    method = 'users.get'
    params = {
        'user_ids': ','.join(map(lambda user_id: str(user_id), user_ids)),
        'access_token': config_data['access_token'],
        'v': CURRENT_VK_VERSION
    }

    request = f'GET https://{HOST_ADDR}/method/{method}?{format_params(params)} HTTP/1.1\n'
    request += f'Host: {HOST_ADDR}\n'
    request += '\n'

    sock.send(request.encode())
    response = receive(sock)
    response_body = response.split('\r\n\r\n')[-1]
    accounts = json.loads(response_body)['response']

    full_names = []
    for account in accounts:
        if account['first_name'] == 'DELETED':
            full_names.append(account['first_name'])
        else:
            full_names.append(account['first_name'] + ' ' + account['last_name'])
    return full_names


def main():
    context = ssl.create_default_context()
    with socket.create_connection((HOST_ADDR, PORT)) as sock:
        sock.settimeout(5)
        with context.wrap_socket(sock, server_hostname=HOST_ADDR) as ssl_sock:
            print(get_friends(ssl_sock, config_data['user_id']))


if __name__ == '__main__':
    main()
