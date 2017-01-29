import nmap
from termcolor import colored
import telnetlib

lhosts = []  # writes live hosts that are found here
commonAdminPorts = [21, 22, 23, 25, 135, 3389]  # removed 80/443; causing problems
vhosts = []  # hosts that have open admin ports

users = ["", "admin"]  # usernames to test
passwords = ["", "password"]  # passwords to test


# define class for hosts with open admin ports
class VulnHost:
    # open admin ports added here
    ports = []
    # defins hosts ip address
    def __init__(self, ipaddr):
        self.ip = ipaddr
    # function addes open admin port to list
    def add_vport(self, port):
        self.ports.append(port)


# Checks for hosts that are alive on the network
def live_hosts(nm):
    print "[*] scanning for live hosts..."
    nm.scan(hosts='127.0.0.1', arguments='-sn')  # ping scan to check for live hosts
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    # prints the hosts that are alive
    for host, status in hosts_list:
        print('[+] {0}   is {1}'.format(colored(host, 'yellow'), colored(status, 'green')))
        lhosts.append(host)  # adds live hosts to list to scan for open admin ports


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


# Function scans for common admin ports that might be open
def admin_scanner(nm):
    print "[*] scanning for open admin ports..."
    x = 0
    for lhost in lhosts:
        x += 1
        b = 'a' + str(x)  # unique class identifier
        print "[*] checking {0} for open admin ports...".format(lhost)
        nm.scan(lhost, str(commonAdminPorts))  # nmap scan command
        lport = nm[lhost]['tcp'].keys()  # retrieves tcp port results from scan
        lport.sort()  # sorts ports
        for port in lport:
            sop = nm[lhost]['tcp'][port]['state']  # defines port state variable
            if sop == 'open':  # checks to see if status is open
                if b not in vhosts:  # checks to see if class has already been created
                    b = VulnHost(lhost)  # adds host to class if it doesn't exist
                    vhosts.append(b)  # appends vulnerable host to list
                b.add_vport(port)  # adds open port to list to check in the class
                print '[+] port : %s\t > %s' % (colored(port, 'yellow'), colored(sop, 'green'))
            else:
                print '[+] port : %s\t > %s' % (colored(port, 'yellow'), sop)


# Checks to see which open admin porst each host has
# Then runs the function to check default credentials
def check_vports():
    print "[*] testing vulnerable host ip address..."
    for vhost in vhosts:
        print vhost.ip
        for port in vhost.ports:
            if port == 23:
                check_telnet(vhost)


# Trys to connect via Telnet with common credentials
# Then it prints the results of the connection attempt
def check_telnet(vhost):
    print "[*] testing telnet connection..."
    host = vhost.ip
    t = telnetlib.Telnet()
    print "[*] opening telnet connection..."
    for user in users:
        x = 0
        while x < len(passwords):
            try:
                print host  # for debug
                print passwords[x]  # for debug
                t.open(host, "23", 1)  # open telnet connection(ipaddr, port, timeout)
                t.read_until("login: ")
                t.write(user + "\n")
                t.read_until("password: ")
                t.write(passwords[x] + "\n")
                t.write("ls\n")
                t.write("exit\n")
                print t.read_all()
                x += 1
            except Exception as e:
                print "[!] ", e
                exit(0)


def main():
    print "[*] initializing port scanner..."
    nm = nmap.PortScanner()  # defines port scanner function to pass to each function
    live_hosts(nm)  # checks for live hosts
    admin_scanner(nm)  # checks for open admin ports
    check_vports()  # tests open ports for default credentials


if __name__ == "__main__":
    main()

