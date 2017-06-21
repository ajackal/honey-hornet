#! /usr/bin/env python

import nmap
from termcolor import colored
import telnetlib
from ftplib import FTP
from pexpect import pxssh
import optparse
from threading import Thread
from datetime import datetime
import httplib


totalhosts = []  # total number of hosts, for calculating percentages
lhosts = []  # writes live hosts that are found here
vhosts = []  # hosts that have open admin ports


# define class for each vulnerable host
class VulnHost(object):
    # defines hosts ip address
    # creates ports list
    # creates a credentials list
    # creates a list to hold banners
    # assigns itself the vulnerable IP
    def __init__(self, ipaddr):
        self.ports = []
        self.p_creds = []
        self.banner = []
        self.ip = ipaddr

    # function adds open admin port to list
    def add_vport(self, port):
        self.ports.append(port)

    # ports with default credentials
    def put_creds(self, newcreds):
        self.p_creds.append(newcreds)

    # adds port, banner to banner list
    def put_banner(self, port, banner_txt, status, reason, headers):
        self.banner.append(':{0} {1} {2} {3}\n{4}\n'.format(port, status, reason, banner_txt, headers))


# define a class to check for open ports
class CheckAdminPorts(Thread):

    def __init__(self, nm, lhosts):
        # starts the Thread
        # assigns the list of live hosts
        # assigns NMAP
        Thread.__init__(self)
        self.lhosts = lhosts
        self.nm = nm

    # Function runs automatically after the class is instantiated
    # Tests all live host for open 'admin' ports
    # if an open port is found, it instantiates a class for that host
    # and records all the open or filtered ports
    def run(self):
        print "[*] scanning for open admin ports..."
        x = 0
        for lhost in self.lhosts:
            x += 1
            b = 'a' + str(x)  # unique class identifier
            print "[*] checking {0} for open admin ports...".format(lhost)
            self.nm.scan(lhost, str(commonAdminPorts))  # nmap scan command
            lport = self.nm[lhost]['tcp'].keys()  # retrieves tcp port results from scan
            lport.sort()  # sorts ports
            y = 0
            for port in lport:
                try:
                    sop = self.nm[lhost]['tcp'][port]['state']  # defines port state variable
                    if sop != 'closed':  # checks to see if status is open
                        if b not in vhosts:  # checks to see if host already has an object
                            b = VulnHost(lhost)  # creates an object for that host if it doesn't exist
                            vhosts.append(b)  # appends vulnerable host to list
                        b.add_vport(port)
                        print '[+] port : %s >> %s' % (colored(port, 'yellow'), colored(sop, 'green'))
                    else:
                        y += 1
                except Exception as error:
                    log_error(error)
                if y == len(lport):
                    print '[!] No open ports found.'


# Checks to see which open admin ports each host has
# Then runs the function to check default credentials
class CheckVports(Thread):

    def __init__(self, vhosts):
        Thread.__init__(self)
        self.vhosts = vhosts

    # Function runs automatically after the class is instantiated
    # Checks to see what vulnerable ports is open for each host
    # Then runs the appropriate function to test credentials
    def run(self):
        for vhost in self.vhosts:
            print '[*] checking >> {0}'.format(vhost.ip)
            if 21 in vhost.ports:
                self.check_ftp(vhost)
            if 22 in vhost.ports:
                self.check_ssh(vhost)
            telnet_ports = [23, 2332]
            for telnet_port in telnet_ports:
                if telnet_port in vhost.ports:
                    self.check_telnet(vhost)
            http_ports = [8000, 8080, 8081, 8090, 9191, 9443]
            for http_port in http_ports:
                if http_port in vhost.ports:
                    self.banner_grab(vhost, http_port)

    # Tries to connect via Telnet with common credentials
    # Then it prints the results of the connection attempt
    def check_telnet(self, vhost):
        host = vhost.ip
        print "[*] Testing Telnet connection on {0}...".format(host)
        if 2332 in vhost.ports:
            port = 2332
        else:
            port = 23
        for user in users:
            x = 0
            for password in passwords:
                try:  # open telnet connection(ipaddr, port, timeout)
                    t = telnetlib.Telnet(host, port, 1)
                    tl = t.read_some()
                    if "login: " in tl:
                        t.write(user + "\n")
                        t.read_until("Password: ")
                        t.write(passwords[x] + "\n")
                        t.write("ls\n")
                        t.write("exit\n")
                        po = t.read_all()
                        if "logout" in po:
                            newcreds = host + ",telnet,23," + user + "," + passwords[x]
                            vhost.put_creds(newcreds)
                            print "[!] Success for Telnet! host: {0}, user: {1}, password: {2}".format(host,
                                                                colored(user, 'yellow'), colored(passwords[x], 'green'))
                            break
                    else:
                        break
                except Exception as error:
                    if "Connection refused" in error:
                        log_error(error)
                        break
                    else:
                        log_error(error)
                        x += 1
                        if x == len(passwords):
                            print "[!] Password not found."
                            # print "[!] ", e  # prints thrown exception, for debug
                            # TODO: fix looping issue, password found, continues to test passwords

    # Function checks the FTP service for all users and passwords given
    # also tests for anonymous log-ins and does an FTP banner grab
    def check_ftp(self, vhost):
        host = vhost.ip
        print "[*] Testing FTP connection on {0}...".format(host)
        try:
            f = FTP(host)
            f.login()
            f.quit()
            fw = f.getwelcome()
            print "[+] Anonymous FTP connection {0} on {1}.".format(colored("successful", "green"), host)
            newcreds = host + ',ftp,21,anon,,' + fw
            vhost.put_creds(newcreds)
            print "[+] FTP server responded with {0}".format(fw)
        except Exception as error:
            log_error(error)
        for user in users:
            x = 0
            while x < len(passwords):
                try:
                    f = FTP()
                    fc = f.connect(host, 21, 1)
                    if fc is True:
                        fw = f.getwelcome()
                        print "[*] FTP server returned %s", fw
                        f.login(user, passwords[x])
                        f.close()
                        newcreds = host + ",ftp,21," + user + ',' + passwords[x] + ',' + fw
                        vhost.put_creds(newcreds)
                        print "[!] Success for FTP! user: {0}, password: {1}".format(colored(user, 'yellow'),
                                                                                     colored(passwords[x], 'green'))
                    break
                except Exception as error:
                    log_error(error)
                    x += 1
                    if x == len(passwords):
                        print "[!] Password not found."

    # Function tests the SSH service with all of the users and passwords given
    def check_ssh(self, vhost):
        host = vhost.ip
        print "[*] Testing SSH service on {0}...".format(host)
        for user in users:
            try:
                for password in passwords:
                    found = False
                    try:
                        s = pxssh.pxssh()
                        s.login(host, user, password)
                        print "[!] Success for SSH! user: {0}, password: {1}".format(colored(user, 'yellow'),
                                                                                     colored(password,
                                                                                             'green'))
                        newcreds = host + ',ssh,22,' + user + ',' + password
                        vhost.put_creds(newcreds)
                        s.logout()
                        s.close()
                    except Exception as error:
                        log_error(error)
                        pass
                        # add something here to close openSSH prompt (only occurs when using PyCharm on Linux)
            except Exception as error:
                log_error(error)

    # simple banner grab with httplib
    def banner_grab(self, vhost, http_port):
        host = vhost.ip
        print "[*] Grabbing banner from {0}".format(host)
        try:
            conn = httplib.HTTPConnection(host, http_port)
            conn.request("GET", "/")
            r1 = conn.getresponse()
            banner_txt = r1.read(1000)
            headers = r1.getheaders()
            print r1.status, r1.reason
            # puts banner into the class instance of the host
            vhost.put_banner(http_port, banner_txt, r1.status, r1.reason, headers)
        except Exception as error:
            log_error(error)


# Function parses either the default files or user input files
# into the appropriate lists to run the program
def inputs(ufile, pfile, ports):
    # TODO: have ports file read to dictionary, key=port, value=protocol

    input_list = [ufile, pfile, ports]

    global users
    global passwords
    global commonAdminPorts

    for x in input_list:
        if x is not None:
            with open(x, 'r') as f:
                if x is ufile:
                    users = f.read().splitlines()
                elif x is pfile:
                    passwords = f.read().splitlines()
                elif x is ports:
                    commonAdminPorts = [int(x) for x in f.read().split()]
        else:
            with open('users.txt', 'r') as f:
                users = f.read().splitlines()
            with open('passwords.txt', 'r') as f:
                passwords = f.read().splitlines()
            with open('ports.txt', 'r') as f:
                commonAdminPorts = [int(x) for x in f.read().split()]


# Function scans the list or CIDR block to see which hosts are alive
# writes the live hosts to the 'lhosts' list
# also calculates the percentage of how many hosts are alive
def live_hosts(nm, addrs, iL):
    print "[*] scanning for live hosts..."
    try:
        if iL is False:
            nm.scan(hosts=addrs, arguments='-sn')  # ping scan to check for live hosts
        else:
            nm.scan(arguments='-sn -iL ' + addrs)
    except Exception as error:
        log_error(error)
    try:
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        # prints the hosts that are alive
        for host, status in hosts_list:
            print('[+] {0} is {1}'.format(colored(host, 'yellow'), colored(status, 'green')))
            lhosts.append(host)  # adds live hosts to list to scan for open admin ports
        if iL is True:
            global live
            live = len(lhosts)
            global percentage
            percentage = 100 * (float(live) / float(total))
            print "[+] {0} out of {1} hosts are alive or {2}%".format(live, total, percentage)
    except Exception as error:
        log_error(error)

# splits the list of hosts into two separate lists
# one list is used when creating each thread
def split_hosts(hosts):
    half = len(hosts)/2
    return hosts[:half], hosts[half:]


# Function scans for common admin ports that might be open
# splits live hosts lists in two
# creates two threads, one for each new list
# this speeds up scanning by 50%
def admin_scanner(nm):
    print "[*] scanning for open admin ports..."
    try:
        lhosts0, lhosts1 = split_hosts(lhosts)
        lhosts0a, lhosts0b = split_hosts(lhosts0)
        lhosts1a, lhosts1b = split_hosts(lhosts1)
        t0a = CheckAdminPorts(nm, lhosts0a)
        t0b = CheckAdminPorts(nm, lhosts0b)
        t1a = CheckAdminPorts(nm, lhosts1a)
        t1b = CheckAdminPorts(nm, lhosts1b)
        t0a.start()
        t0b.start()
        t1a.start()
        t1b.start()
        t0a.join()
        t0b.join()
        t1a.join()
        t1b.join()
    except Exception as error:
        log_error(error)

# Function tests hosts for default credentials on open 'admin' ports
# splits the list of vulnerable hosts in two
# creates two threads, one for each list
# speeds up scanning by 50%
# now creates four threads.
def run_thread():
    print "[*] Testing vulnerable host ip addresses..."
    try:
        vhosts0, vhosts1 = split_hosts(vhosts)
        vhosts0a, vhosts0b = split_hosts(vhosts0)
        vhosts1a, vhosts1b = split_hosts(vhosts1)
        t0a = CheckVports(vhosts0a)
        t0b = CheckVports(vhosts0b)
        t1a = CheckVports(vhosts1a)
        t1b = CheckVports(vhosts1b)
        t0a.start()
        t0b.start()
        t1a.start()
        t1b.start()
        t0a.join()
        t0b.join()
        t1a.join()
        t1b.join()
    except Exception as error:
        log_error(error)

# Function records all of the results from each instance of the class in to a csv report
def rec_results(ofile, iL):
    print '[*] recording results...'
    with open(ofile, 'a+') as f:
        if iL is True:
            stats = 'live,total\n{0},{1}\n'.format(live, total)
            f.write(stats)
        headers_ports = 'host,port,status,header\n'
        f.write(headers_ports)
        for vhost in vhosts:
            for port in vhost.ports:
                for x in vhost.banner:
                    if str(port) in x:
                        y = str(vhost.ip) + ',' + str(port) + ",open,yes\n"
                        f.write(y)
                    else:
                        y = str(vhost.ip) + ',' + str(port) + ",open,no\n"
                        f.write(y)
        headers_creds = 'host,protocol,port,user,password,misc\n'
        f.write(headers_creds)
        for vhost in vhosts:
            # print vhost.p_creds  # returns correct values
            x = str(vhost.p_creds).strip("['']") + '\n'  # assigns p_creds to x, correctly
            f.write(x)  # writes x to file, also correctly
            bfile = 'banners_' + ofile
            with open(bfile, 'a+') as b:
                for x in vhost.banner:
                    y = str(vhost.ip) + ' ' + str(x)
                    b.write(y)


def log_error(error):
    time_now = datetime.now()
    log_error = str(time_now) + ":" + str(error) + "\n"
    with open('error.log', 'a') as f:
        f.write(log_error)
        print "[*] Error logged: {0}".format(error)


def main():
    start_time = datetime.now()

    parser = optparse.OptionParser('usage: %prog [-i <file listing IPs> OR -c <CIDR block>] -u <users.txt> '
                                   '-p <passwords.txt> -o <output file (optional)>')
    parser.add_option('-i', dest='ifile', type='string', help='import IP addresses from file, cannot be used with -c')
    parser.add_option('-c', dest='cidr', type='string', help='cidr block or localhost, cannot be used with -i')
    parser.add_option('-u', dest='ufile', type='string', help='imports users from file; else: uses default list')
    parser.add_option('-p', dest='pfile', type='string', help='imports passwords from file; else: uses default list')
    parser.add_option('-o', dest='ofile', type='string', help='output to this file; else output to stdout')
    parser.add_option('-a', dest='ports', type='string', help='import ports from file')
    (options, args) = parser.parse_args()

    ifile = options.ifile
    cidr = options.cidr
    ofile = options.ofile
    ufile = options.ufile
    pfile = options.pfile
    ports = options.ports

    inputs(ufile, pfile, ports)

    if ifile is not None and cidr is not None:
        print "[!] Cannot have two input options!"
        print parser.usage
        exit(0)
    elif ifile is None and cidr is None:
        print "[!] Must define something to scan!"
        print parser.usage
        exit(0)
    else:
        print "[*] initializing port scanner..."
        nm = nmap.PortScanner()  # defines port scanner function to pass to each function
        if ifile is not None:
            addrs = ifile
            iL = True
            with open(addrs, 'r') as f:
                totalhosts = f.readlines()
                global total
                total = len(totalhosts)
        else:
            addrs = cidr
            iL = False
        try:
            live_hosts(nm, addrs, iL)  # checks for live hosts
            # TODO: add option to disable port scan and just test ports listed in file.
            admin_scanner(nm)  # checks for open admin ports
            run_thread()
        except Exception as e:
            log_error(error)
        finally:
            if ofile is not None:
                rec_results(ofile, iL)
            print datetime.now() - start_time


if __name__ == "__main__":
    main()
