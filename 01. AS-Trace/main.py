from urllib.request import urlopen
from scapy.all import *
from prettytable import PrettyTable
import re

IP_GROUPS_RE = re.compile('(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})')
IP_RE = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
AS_RE = re.compile('[Oo]riginA?S?: *([\d\w]+?)\n')
COUNTRY_RE = re.compile('[Cc]ountry: *([\w]+?)\n')
PROVIDER_RE = re.compile('mnt-by: *([\w\d-]+?)\n')
tracert_is_done = False

def animate_loading():
    global tracert_is_done
    for c in itertools.cycle(['|', '/', '—', '\\']):
        if tracert_is_done:
            break
        print('\rIP address tracing... ' + c, end='', flush=True)
        time.sleep(0.3)
    print('\nDone!\n')


def trace_ips(name):
    global tracert_is_done
    t = threading.Thread(target=animate_loading)
    t.start()  # запуск анимации загрузки в консоли

    cmd_line = f"tracert {name}"
    p = os.popen(cmd_line)
    stdout = p.read()
    tracert_is_done = True
    return IP_RE.findall(stdout)[1:]


def get_first_appearance(html, regex):
    try:
        return regex.findall(html)[0]
    except:
        return ''


def get_ip_info(ip):
    if ip_is_gray(ip):
        return ip, '', '', ''
    url = f'https://www.nic.ru/whois/?searchWord={ip}'
    try:
        with urlopen(url) as f:
            response_html = f.read().decode('utf-8')
            return ip, get_first_appearance(response_html, AS_RE), get_first_appearance(response_html, PROVIDER_RE), \
                get_first_appearance(response_html, COUNTRY_RE)
    except:
        return ip, '', '', ''


def ip_is_gray(ip: str):
    ip_groups = re.search(IP_GROUPS_RE, ip)

    if ip_groups.group(1) == '10':
        return True
    if ip_groups.group(1) == '192' and ip_groups.group(2) == '168':
        return True

    group2 = int(ip_groups.group(2))
    if ip_groups.group(1) == '100' and group2 >= 64 and group2 <= 127:
        return True
    if ip_groups.group(1) == '172' and group2 >= 16 and group2 <= 31:
        return True

    return False


def info_to_table(ips_info):
    column_names = ['№', 'IP', 'AS Name', 'Provider', 'Country']
    table_data = []
    number = 1
    for ip_info in ips_info:
        table_data.append(number)
        table_data.extend(ip_info)
        number += 1
    columns_number = len(column_names)
    table = PrettyTable(column_names)
    while table_data:
        table.add_row(table_data[:columns_number])
        table_data = table_data[columns_number:]
    return table


def main():
    print('Please, enter domain name:')
    domain_name = input()
    ips = trace_ips(domain_name)
    ips_info = []
    for ip in ips:
        ips_info.append(get_ip_info(ip))
    table = info_to_table(ips_info)

    time.sleep(0.3)  # прежде чем что-то вывести
    print(table)


if __name__ == '__main__':
    main()
