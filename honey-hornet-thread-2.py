#! /usr/bin/env python

import nmap
from termcolor import colored
import telnetlib
from ftplib import FTP
from pexpect import pxssh
import optparse
from multiprocessing import Process

lhosts = []  # writes live hosts that are found here
commonAdminPorts = [21, 22, 23, 25, 135, 3389]  # removed 80/443; causing problems
vhosts = []  # hosts that have open admin ports

users = ["mike", "", "admin"]  # usernames to test
passwords = ["", "password", "12345"]  # passwords to test


# define class for hosts with open admin ports
class VulnHost(object):
    # defines hosts ip address
    # creates ports dictionary
    def __init__(self, ipaddr):
        self.ports = []
        self.p_creds = []
        self.ip = ipaddr

    # function addes open admin port to list
    def add_vport(self, port):
        self.ports.append(port)

    # ports with default credentials
    def put_creds(self, newcreds):
        self.p_creds.append(newcreds)


def live_hosts(nm, addrs, iL):
    print "[*] scanning for live hosts..."
    if iL is False:
        nm.scan(hosts=addrs, arguments='-sn')  # ping scan to check for live hosts
    else:
        nm.scan(arguments='-sn -iL ' + addrs)
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    # prints the hosts that are alive
    for host, status in hosts_list:
        print('[+] {0} is {1}'.format(colored(host, 'yellow'), colored(status, 'green')))
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
# TODO: add multi-threading to speed up scan
def admin_scanner(nm):
    print "[*] scanning for open admin ports..."
    x = 0
    for lhost in lhosts:
        x += 1
        b = 'a' + str(x)  # unique class identifier
        print "[*] checking {0} for open admin ports...".format(lhost)
        nm.scan(lhost, str(commonAdminPorts))  # nmap scan command
        try:
            lport = nm[lhost]['tcp'].keys()  # retrieves tcp port results from scan
            lport.sort()  # sorts ports
        except Exception:
            raise
        y = 0
        for port in lport:
            try:
                sop = nm[lhost]['tcp'][port]['state']  # defines port state variable
                if sop == 'open':  # checks to see if status is open
                    if b not in vhosts:  # checks to see if host already has an object
                        b = VulnHost(lhost)  # creates an object for that host if it doesn't exist
                        vhosts.append(b)  # appends vulnerable host to list
                    b.add_vport(port)  # adds open port to dictionary with value: True
                    print '[+] port : %s >> %s' % (colored(port, 'yellow'), colored(sop, 'green'))
                else:
                    y += 1
                    # print '[+] port : %s\t > %s' % (colored(port, 'yellow'), sop)  # displays closed ports
            except Exception:
                raise
            if y == len(lport):
                print '[!] No open ports found.'


# Checks to see which open admin ports each host has
# Then runs the function to check default credentials
def check_vports():
    def run_thread(vhost):
        print '[*] checking >> {0}'.format(vhost.ip)
        if 21 in vhost.ports:
            check_ftp(vhost)
        if 22 in vhost.ports:
            check_ssh(vhost)
        if 23 in vhost.ports:
            check_telnet(vhost)
    print "[*] testing vulnerable host ip address..."
    for vhost in vhosts:
        p = Process(target=run_thread, args=(vhost,))
        p.start()
        p.join()


# Trys to connect via Telnet with common credentials
# Then it prints the results of the connection attempt
def check_telnet(vhost):
    host = vhost.ip
    # print "[*] testing telnet connection on {0}...".format(host)
    # while success is False: # causes infinite loop if connection refused
    for user in users:
        x = 0
        for password in passwords:
            try:  # open telnet connection(ipaddr, port, timeout)
                t = telnetlib.Telnet(host, 23, 1)
                tl = t.read_some()
                if "login: " in tl:
                    t.write(user + "\n")
                    t.read_until("Password: ")
                    t.write(passwords[x] + "\n")
                    t.write("ls\n")
                    t.write("exit\n")
                    po = t.read_all()
                    if "logout" in po:
                        newcreds = host + ";telnet;23;" + user + ';' + passwords[x]
                        vhost.put_creds(newcreds)
                        print "[!] Success for TELNET! host: {0}, user: {1}, password: {2}".format(host,
                                                        colored(user, 'yellow'), colored(passwords[x], 'green'))
                        break
                else:
                    break
            except Exception as e:
                if "Connection refused" in e:
                    break
                else:
                    print e
                    x += 1
                    if x == len(passwords):
                        print "[!] Password not found."
                        # print "[!] ", e  # prints thrown exception, for debug
                        # TODO: fix looping issue, password found, continues to test passwords


def check_ftp(vhost):
    host = vhost.ip
    # print "[*] testing ftp connection on {0}...".format(host)
    try:
        f = FTP(host)
        f.login()
        f.quit()
        fw = f.getwelcome()
        print "[+] Anonymous FTP connection {0} on {1}.".format(colored("successful", "green"), host)
        newcreds = host + ';ftp;21;anon;;' + fw
        vhost.put_creds(newcreds)
        print "[+] FTP server responded with {0}".format(fw)
    except Exception as e:
        print "[!] Anonymous FTP login failed: {0}".format(e)
        pass
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
                    newcreds = host + ";ftp;21;" + user + ';' + passwords[x] + ';' + fw
                    vhost.put_creds(newcreds)
                    print "[!] Success for FTP! user: {0}, password: {1}".format(colored(user, 'yellow'),
                                                                                 colored(passwords[x], 'green'))
                break
            except Exception:
                # print "[!] Something went wrong: {0}".format(e)
                x += 1
                if x == len(passwords):
                    print "[!] Password not found."


def check_ssh(vhost):
    host = vhost.ip

    # print "[*] testing SSH service..."

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
                    newcreds = host + ';ssh;22;' + user + ';' + password
                    vhost.put_creds(newcreds)
                    s.logout()
                    s.close()
                except Exception:
                    pass
                    # add something here to close openSSH prompt
        except Exception as e:
            print str(e)


def rec_results(ofile):
    print '[*] recording results...'
    with open(ofile, 'a+') as f:
        headers = 'host;protocol;port;user;password;misc\n'
        f.write(headers)
        for vhost in vhosts:
                # print vhost.p_creds  # returns correct values
                x = str(vhost.p_creds).strip("['']") + '\n' # assigns p_creds to x, correctly
                f.write(x)  # writes x to file, also correctly


def main():
    new_pw = raw_input("Password to add to list: ")
    passwords.append(new_pw)

    parser = optparse.OptionParser('usage: %prog [-i <inputfile> OR -c <CIDR block>] -o <\
                                   output file (optional)>')
    parser.add_option('-i', dest='ifile', type='string', help='read from file for IP\
                      addresses')
    parser.add_option('-c', dest='cidr', type='string', help='cidr block or localhost')
    parser.add_option('-o', dest='ofile', type='string', help='output to this file,\
                      if not defined will out put to stdout')
    parser.add_option('-p', dest='ports', type='string', help='read from file for ports')
    (options, args) = parser.parse_args()

    ifile = options.ifile
    cidr = options.cidr
    ofile = options.ofile
    ports = options.ports

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
        else:
            addrs = cidr
            iL = False
        live_hosts(nm, addrs, iL)  # checks for live hosts
        admin_scanner(nm)  # checks for open admin ports
        check_vports()  # tests open ports for default credentials
        if ofile is not None:
            rec_results(ofile)


if __name__ == "__main__":
    main()
