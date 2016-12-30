from nmap import nmap


lhosts = []  # live hosts

def find_live():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')
    hosts_list = [(x,nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
       print('{0}:{1}'.format(host,status))
       lhosts.append(host)


def scan_ports():
    commonAdminPorts = "21,22,23,25,80,135,443,3389"
    nm = nmap.PortScanner()
    for lhost in lhosts:
       nm.scan(hosts=lhost, arguments='-sT -p' + commonAdminPorts)
       print('port: %s\tstate : %s' % (port, nm[host][proto][port]['state']))


def main():
    find_live()
    scan_ports()


if __name__ is "__main__":
    main()

