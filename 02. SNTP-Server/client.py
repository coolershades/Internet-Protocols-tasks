from datetime import datetime
import SNTPClient

TIME1970 = 2208988800  # секунд прошло с 01.01.1900 до 01.01.1970


SERVER_IPADDRESS = '127.0.0.1'
PORT = 10123

client = SNTPClient.Client()
print('Before sync time:', datetime.fromtimestamp(client.get_current_time() - TIME1970))

client.synchronize((SERVER_IPADDRESS, PORT))
print('\nClock offset:', client.clock_offset)
print('After sync time:', datetime.fromtimestamp(client.get_current_time() - TIME1970))

client.shutdown()
