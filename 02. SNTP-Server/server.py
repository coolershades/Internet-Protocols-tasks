from datetime import datetime
import time
import json
from SNTPServer import Server

TIME1970 = 2208988800  # секунд прошло с 01.01.1900 до 01.01.1970


PRIMARY_TIME_SERVER = '195.218.227.166'  # '0.ru.pool.ntp.org'
SERVER_IPADDRESS = '127.0.0.1'
PORT = 10123
CONFIG_FILENAME = 'conf.json'



def get_delay():
    with open(CONFIG_FILENAME, 'r') as c_file:
        d = json.load(c_file)
        return d['delay']


server = Server(SERVER_IPADDRESS, PORT, PRIMARY_TIME_SERVER, delay=get_delay())  # delay = 5 min

act_time = time.time()
print('Actual time:\t\t\t', act_time, datetime.fromtimestamp(act_time))

before_sync = server.get_current_time()
print('Server time before syncing:\t', before_sync, datetime.fromtimestamp(before_sync - TIME1970))
server.synchronize()

print('Clock offset:\t\t\t', server.clock_offset)
after_sync = server.get_current_time()
print('Server time after syncing:\t', after_sync, datetime.fromtimestamp(after_sync - TIME1970))

server.process_request()
