#! /usr/bin/env python

import nmap
from termcolor import colored
import telnetlib
from ftplib import FTP
from pexpect import pxssh
import optparse
from threading import Thread
from datetime import datetime
import socket

totalhosts = []
lhosts = []  # writes live hosts that are found here
commonAdminPorts = [21, 22, 554, 2332, 9443, 8000, 8080, 8081, 9000, 9191, 41592]
vhosts = []  # hosts that have open admin ports

users = ['admin', '', 'user', 'bob']  # usernames to test
passwords = ['12345', '', 'password']  # passwords to test


# define class for hosts with open admin ports
class VulnHost(object):
    # defines hosts ip address
    # creates ports dictionary
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
    def put_banner(self, port, banner_txt):
        self.banner.append('{0}:{1}'.format(port, banner_txt))


class CheckAdminPorts(Thread):

    def __init__(self, nm, lhosts):
        Thread.__init__(self)
        self.lhosts = lhosts
        self.nm = nm

    def run(self):
        print "[*] scanning for open admin ports..."
        x = 0
        for lhost in self.lhosts:
            x += 1
            b = 'a' + str(x)  # unique class identifier
            print "[*] checking {0} for open admin ports...".format(lhost)
            self.nm.scan(lhost, str(commonAdminPorts))  # nmap scan command
            try:
                lport = self.nm[lhost]['tcp'].keys()  # retrieves tcp port results from scan
                lport.sort()  # sorts ports
            except Exception:
                raise
            y = 0
            for port in lport:
                try:
                    sop = self.nm[lhost]['tcp'][port]['state']  # defines port state variable
                    if sop == 'open':  # checks to see if status is open
                        if b not in vhosts:  # checks to see if host already has an object
                            b = VulnHost(lhost)  # creates an object for that host if it doesn't exist
                            vhosts.append(b)  # appends vulnerable host to list
                        b.add_vport(port)  # adds open port to dictionary with value: True
                        print '[+] port : %s >> %s' % (colored(port, 'yellow'), colored(sop, 'green'))
                    else:
                        y += 1
                        # displays closed ports
                        # print '[+] port : %s\t > %s' % (colored(port, 'yellow'), sop)
                except Exception:
                    raise
                if y == len(lport):
                    print '[!] No open ports found.'


# Checks to see which open admin ports each host has
# Then runs the function to check default credentials
class CheckVports(Thread):

    def __init__(self, vhosts):
        Thread.__init__(self)
        self.vhosts = vhosts

    def run(self):
        for vhost in self.vhosts:
            print '[*] checking >> {0}'.format(vhost.ip)
            if 21 in vhost.ports:
                self.check_ftp(vhost)
            if 22 in vhost.ports:
                self.check_ssh(vhost)
            if 2332 in vhost.ports:
                self.check_telnet(vhost)
            http_ports = [8000, 8080, 8081, 9191]
            for http_port in http_ports:
                if http_port in vhost.ports:
                    self.banner_grab(vhost, http_port)

    # Trys to connect via Telnet with common credentials
    # Then it prints the results of the connection attempt
    def check_telnet(self, vhost):
        host = vhost.ip
        # print "[*] testing telnet connection on {0}...".format(host)
        # while success is False: # causes infinite loop if connection refused
        for user in users:
            x = 0
            for password in passwords:
                try:  # open telnet connection(ipaddr, port, timeout)
                    t = telnetlib.Telnet(host, 2332, 1)
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
                            print "[!] Success for TELNET! host: {0}, user: {1}, password: {2}".format(host,
                                                            colored(user,'yellow'), colored(passwords[x],'green'))
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

    def check_ftp(self, vhost):
        host = vhost.ip
        # print "[*] testing ftp connection on {0}...".format(host)
        try:
            f = FTP(host)
            f.login()
            f.quit()
            fw = f.getwelcome()
            print "[+] Anonymous FTP connection {0} on {1}.".format(colored("successful", "green"), host)
            newcreds = host + ',ftp,21,anon,,' + fw
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
                        newcreds = host + ",ftp,21," + user + ',' + passwords[x] + ',' + fw
                        vhost.put_creds(newcreds)
                        print "[!] Success for FTP! user: {0}, password: {1}".format(colored(user, 'yellow'),
                                                                                     colored(passwords[x], 'green'))
                    break
                except Exception:
                    # print "[!] Something went wrong: {0}".format(e)
                    x += 1
                    if x == len(passwords):
                        print "[!] Password not found."

    def check_ssh(self, vhost):
        host = vhost.ip

        # print "[*] testing SSH service on {0}...".format(vhost.ip)

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
                    except Exception:
                        pass
                        # add something here to close openSSH prompt
            except Exception as e:
                print str(e)

    # simple banner grab with sockets
    # TODO: replace socket with httplib, much better
    def banner_grab(self, vhost, http_port):
        host = vhost.ip
        s = socket.socket()
        s.connect(('http://{0}'.format(host), http_port))
        s.send('GET / HTTP/1.1\n\n')
        banner_txt = s.recv(850)
        print banner_txt
        vhost.put_banner(http_port, banner_txt)


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
    if iL is True:
        global live
        live = len(lhosts)
        global percentage
        percentage = 100 * (float(live) / float(total))
        print "{0} out of {1} hosts are alive or {2}%".format(live, total, percentage)


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

    lhosts0, lhosts1 = split_hosts(lhosts)
    t1 = CheckAdminPorts(nm, lhosts0)
    t2 = CheckAdminPorts(nm, lhosts1)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def split_hosts(hosts):
    half = len(hosts)/2
    return hosts[:half], hosts[half:]


def run_thread():
    vhosts0, vhosts1 = split_hosts(vhosts)

    print "[*] testing vulnerable host ip address..."

    t1 = CheckVports(vhosts0)
    t2 = CheckVports(vhosts1)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def rec_results(ofile, iL):
    print '[*] recording results...'
    with open(ofile, 'a+') as f:
        if iL is True:
            stats = 'live,total\n{0},{1}\n'.format(live, total)
            f.write(stats)
        headers_ports = 'host,port,status\n'
        f.write(headers_ports)
        for vhost in vhosts:
            for port in vhost.ports:
                y = str(vhost.ip) + ',' + str(port) + ",open\n"
                f.write(y)
        headers_creds = 'host,protocol,port,user,password,misc\n'
        f.write(headers_creds)
        for vhost in vhosts:
                # print vhost.p_creds  # returns correct values
                x = str(vhost.p_creds).strip("['']") + '\n'  # assigns p_creds to x, correctly
                f.write(x)  # writes x to file, also correctly


def main():
    start_time = datetime.now()
    new_pw = raw_input("Password to add to list: ")
    passwords.append(new_pw)

    parser = optparse.OptionParser('usage: %prog [-i <inputfile> OR -c <CIDR block>] -o <\
                                   output file (optional)>')
    parser.add_option('-i', dest='ifile', type='string', help='read from file for IP\
                      addresses')
    parser.add_option('-c', dest='cidr', type='string', help='cidr block or localhost')
    parser.add_option('-o', dest='ofile', type='string', help='output to this file,\
                      if not defined will output to stdout')
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
            with open(addrs, 'r') as f:
                totalhosts = f.readlines()
                global total
                total = len(totalhosts)
        else:
            addrs = cidr
            iL = False
        try:
            live_hosts(nm, addrs, iL)  # checks for live hosts
            admin_scanner(nm)  # checks for open admin ports
            run_thread()
        except Exception as e:
            print '[!] there was an error!! {0}'.format(e)
        finally:
            if ofile is not None:
                rec_results(ofile, iL)
            print datetime.now() - start_time


if __name__ == "__main__":
    main()
