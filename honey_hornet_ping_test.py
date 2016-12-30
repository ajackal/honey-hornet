from nmap import nmap

nm = nmap.PortScanner()
nm.scan(hosts='192.168.1.0/24', arguments='-sn')
hosts_list = [(x,nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
    print('{0}:{1}'.format(host,status))
