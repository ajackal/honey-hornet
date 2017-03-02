#! /usr/bin/env python

import sys
import nmap
from termcolor import colored
import telnetlib
from ftplib import FTP
from pexpect import pxssh
import time
from threading import Thread, BoundedSemaphore
import optparse


lhosts = []  # writes live hosts that are found here
commonAdminPorts = [21, 22, 23, 25, 135, 3389]  # removed 80/443; causing problems
vhosts = []  # hosts that have open admin ports


users = ["mike", "", "admin"]  # usernames to test
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
        lport = nm[lhost]['tcp'].keys()  # retrieves tcp port results from scan
        lport.sort()  # sorts ports
        y = 0
        for port in lport:
            sop = nm[lhost]['tcp'][port]['state']  # defines port state variable
            if sop == 'open':  # checks to see if status is open
                if b not in vhosts:  # checks to see if class has already been created
                    b = VulnHost(lhost)  # adds host to class if it doesn't exist
                    vhosts.append(b)  # appends vulnerable host to list
                b.add_vport(port)  # adds open port to list to check in the class
                print '[+] port : %s >> %s' % (colored(port, 'yellow'), colored(sop, 'green'))
            else:
                y += 1
                # print '[+] port : %s\t > %s' % (colored(port, 'yellow'), sop)
        if y == len(lport):
            print '[!] No open ports found.'


# Checks to see which open admin porst each host has
# Then runs the function to check default credentials
def check_vports():
    print "[*] testing vulnerable host ip address..."
    for vhost in vhosts:
        for port in vhost.ports:
            if port == 21:
                check_ftp(vhost)
            if port == 22:
                check_ssh(vhost)
            if port == 23:
                check_telnet(vhost)


# Trys to connect via Telnet with common credentials
# Then it prints the results of the connection attempt
def check_telnet(vhost):
    print "[*] testing telnet connection..."
    host = vhost.ip
    for user in users:
        x = 0
        while x < len(passwords):
            try: # open telnet connection(ipaddr, port, timeout)
                t = telnetlib.Telnet(host, 23, 1)
                t.read_until("login: ")
                t.write(user + "\n")
                t.read_until("Password: ")
                t.write(passwords[x] + "\n")
                t.write("ls\n")
                t.write("exit\n")
                po = t.read_all()
                # sys.stdout.write(po)  for debug purposes
                if "logout" in po:
                    print "[!] Success for TELNET! user: {0}, password: {1}".format(\
                            colored(user, 'yellow'), colored(passwords[x], 'green'))
                x += 1
            except Exception:
                x += 1
                # print "[!] ", e  # prints thrown exception, for debug
    # TODO: add break here to end test
    if x == len(passwords):
        print "[!] Password not found."

        
def check_ftp(vhost):
    print "[*] testing ftp connection..."
    host = vhost.ip
    anon = False
    try:
        f = FTP(host)
        f.login()
        f.quit()
        print "[+] Anonymous FTP connection successful."
        anon = True
    except Exception as e:
        print "[!] Anonymous FTP login failed: {0}".format(e)
        pass
    if anon == False:
        for user in users:
            x = 0
            while x < len(passwords):
                try:
                    f = FTP(host)
                    f.login(user, passwords[x])
                    f.close()
                    print "[!] Success for FTP! user: {0}, password: {1}".format(\
                        colored(user, 'yellow'), colored(passwords[x], 'green'))
                    success = True
                    break
                except Exception as e:
                    # print "[!] Something went wrong: {0}".format(e)
                    x += 1
            continue 
    if x == len(passwords):
        print "[!] Password not found."


def check_ssh(vhost):
    host = vhost.ip

    global Found
    global Fails
    Found = False
    Fails = 0

    max_connections = 5
    connection_lock = BoundedSemaphore(value=max_connections)

    print "[*] testing SSH service..."

    def connect(host,user, password):
        # print "[*] testing ssh {0}:{1}".format(user, password)
        try:
            s = pxssh.pxssh()
            s.login(host, user, password)
            print "[!] Success for SSH! user: {0}, password: {1}".format(colored(user,\
                                                'yellow'), colored(password, 'green'))
            Found = True
            return s
        except Exception as e:
            return Fails + 1
            if 'read_nonblocking' in str(e):
                time.sleep(5)
                s.login(host, user, passwords[x], False)
            elif 'synchronize with original prompt' in str(e):
                time.sleep(1)
                s.login(host, user, passwords[x], False)
                raise
        #finally:
            #try:
                #connection_lock.release()
            #except Exception as e:
                #if e is "ValueError":
                    #raise
                #else:
                    #print e
                    #raise
            # add something here to close openSSH prompt
            # exit(0)
    connection_lock.acquire()
    for user in users:
        try:
            for password in passwords:
                t = Thread(target=connect, args=(host, user, password))
                t.start()
                #t.close()
        except Exception as e:
            print str(e)


def main():
    new_pw = raw_input( "Password to add to list: ")
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

    if ifile != None and cidr != None:
        print "[!] Cannot have two input options!"
        print parser.usage
        exit (0)
    elif ifile == None and cidr == None:
        print "[!] Must define something to scan!"
        print parser.usage
        exit(0)
    else:
        print "[*] initializing port scanner..."
        nm = nmap.PortScanner()  # defines port scanner function to pass to each function
        if ifile != None:
            addrs = ifile
            iL = True
        else:
            addrs = cidr
            iL = False
        live_hosts(nm, addrs, iL)  # checks for live hosts
        admin_scanner(nm)  # checks for open admin ports
        check_vports()  # tests open ports for default credentials


if __name__ == "__main__":
    main()

