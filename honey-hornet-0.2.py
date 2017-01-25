import nmap
from termcolor import colored

lhosts = []  # writes live hosts that are found here
commonAdminPorts = [21, 22, 23, 25, 135, 3389]  # removed 80/443; causing problems
vulnPorts = []

def live_hosts(nm):
#    print "[*] initializing port scanner..."
#    nm = nmap.PortScanner()
    print "[*] scanning for live hosts..."
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')
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
    for lhost in lhosts:
            print "[*] checking {0} for open admin ports...".format(lhost)
            nm.scan(lhost, str(commonAdminPorts))
            lport = nm[lhost]['tcp'].keys()
            lport.sort()
            # sop = nm[lhost]['tcp'][port]['state']
            for port in lport:
                sop = nm[lhost]['tcp'][port]['state']
                if sop == 'open':
                    print '[+] port : %s\t > %s' % (colored(port, 'yellow'), colored(sop, 'green'))
                else:
                    print '[+] port : %s\t > %s' % (colored(port, 'yellow'), sop)



# def check_open_admin():



def main():
    print "[*] initializing port scanner..."
    nm = nmap.PortScanner()
    live_hosts(nm)
    admin_scanner(nm)


if __name__ == "__main__":
    main()

