import nmap
from termcolor import colored
import telnetlib

lhosts = []  # writes live hosts that are found here
commonAdminPorts = [21, 22, 23, 25, 135, 3389]  # removed 80/443; causing problems
vhosts = []

users = []
passwords = []

class VulnHost:

    ports = []

    def __init__(self, ipaddr):
        self.ip = ipaddr

    def add_vport(self, port):
        self.ports.append(port)


def live_hosts(nm):
#    print "[*] initializing port scanner..."
#    nm = nmap.PortScanner()
    print "[*] scanning for live hosts..."
    nm.scan(hosts='127.0.0.1', arguments='-sn')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        print('[+] {0}   is {1}'.format(colored(host, 'yellow'), colored(status, 'green')))
        lhosts.append(host)


# This was the first function I wrote that got it right
# But it didn't display results in a useful manner
# So I rewrote it to the function below this one.
#
# print "[*] scanning for open admin ports..."
# for lhost in lhosts:
#     x = 0
#     while x < len(commonAdminPorts):
#         print "[*] checking {0} for open port on {1}...".format(lhost, commonAdminPorts[x])
#         nm.scan(lhost, str(commonAdminPorts[x]))
#         x += 1
#         lport = nm[lhost]['tcp'].keys()
#         lport.sort()
#         for port in lport:
#             print '[+] port : %s\tstate : %s' % (port, nm[lhost]['tcp'][port]['state'])


def admin_scanner(nm):
    print "[*] scanning for open admin ports..."
    x = 0
    for lhost in lhosts:
        x += 1
        b = 'a' + str(x)
        print "[*] checking {0} for open admin ports...".format(lhost)
        nm.scan(lhost, str(commonAdminPorts))
        lport = nm[lhost]['tcp'].keys()
        lport.sort()
        for port in lport:
            sop = nm[lhost]['tcp'][port]['state']
            if sop == 'open':
                if b not in vhosts:
                    b = VulnHost(lhost)
                    vhosts.append(b)
                b.add_vport(port)
                print '[+] port : %s\t > %s' % (colored(port, 'yellow'), colored(sop, 'green'))
            else:
                print '[+] port : %s\t > %s' % (colored(port, 'yellow'), sop)


def check_vports():
    print "[*] displaying vulnerable host ip address..."
    for vhost in vhosts:
        print vhost.ip
        for port in vhost.ports:
            print port
            if port == 23:
                check_telnet(vhost)


def check_telnet(vhost):
    print "[*] testing telnet connection..."
    host = vhost.ip
    t = telnetlib.Telnet()
    print "[*] opening telnet connection..."
    for user in users:
        try:
            t.open(host)
            t.read_until("login: ")
            t.write(user + "\n")
            t.read_until("password: ")
            t.write(password + "\n")
            t.write("ls\n")
            t.write("exit\n")
            print t.read_all()
        except Exception as e:
            print "[!] ", e


def main():
    print "[*] initializing port scanner..."
    nm = nmap.PortScanner()
    live_hosts(nm)
    admin_scanner(nm)
    check_vports()


if __name__ == "__main__":
    main()

