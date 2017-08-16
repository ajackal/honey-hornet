import nmap
import sxssh


lhosts = []  # maybe dont need
common_admin_ports = [21, 22, 23, etc.]


class VulnHost:

    def __init__(self, ipaddr):
        self.ip = ipaddr
        self.vulnports = []
        self.banner = banner  # maybe dont need this
        self.os = os  # maybe dont need this

    def add_port(self, port):
        self.vulnports.append(port)  # possibly need vulnport

    def add_banner(self, banner):
        self.banner = banner

    def add_os(self, os):
        self.os = os


def live_hosts(ifile):
    while file.open:
    line = read.lines()
    for line in lines:
        sudo nmap -sn "find_live_hosts"
        if host is live:
            a = VulnHost("live_host_ip_addr")
            lhosts.append("live_host_ip")  # maybe dont need
            port_scan(a)


def port_scan(a):
    ipadd = a.ipaddr
    sudo nmap -PN -p "common_admin_ports" ipaddr
#    for lhost in live_hosts:
#        sudo nmap -PN -p "common_admin_ports" "live_host"
        if commonAdminPort is open:
            a.vulnports.append(port)

def main():
    parser = input_file
    live_hosts(ifile)

if __name__ is "__main__":
    main() 

