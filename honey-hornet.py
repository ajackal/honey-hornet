#! /usr/bin/env python

import nmap
from termcolor import colored
import telnetlib
from ftplib import FTP
from pexpect import pxssh
import optparse
import threading
from threading import *
from datetime import datetime
import httplib
import re


max_connections = 10
connection_lock = BoundedSemaphore(value=max_connections)

live_hosts = []  # writes live hosts that are found here
vulnerable_hosts = []  # hosts that have open admin ports


# defines a class for each live host with an open admin port
class VulnerableHost(object):
    # defines hosts ip address
    # creates ports list
    # creates a credentials list
    # creates a list to hold banners
    # assigns itself the vulnerable IP
    def __init__(self, ipaddr):
        self.ports = []
        self.credentials = []
        self.banner = []
        self.ip = ipaddr

    # function adds open admin port to list
    def add_vulnerable_port(self, port):
        self.ports.append(port)

    # ports with default credentials
    def put_credentials(self, newcreds):
        self.credentials.append(newcreds)

    # adds port, banner to banner list
    def put_banner(self, port, banner_txt, status, reason, headers):
        self.banner.append(':{0} {1} {2} {3}\n{4}\n'.format(port, status, reason, banner_txt, headers))


# defines a class to thread the scanning for open ports
def check_admin_ports(live_host, common_admin_ports):
    # Function runs automatically after the class is instantiated
    # Tests all live host for open 'admin' ports
    # if an open port is found, it instantiates a class for that host
    # and records all the open or filtered ports
    try:
        connection_lock.acquire()
        host = live_host
        print "[*] initializing port scanner..."
        nm = nmap.PortScanner()  # defines port scanner function to pass to each function
        print "[*] scanning for open admin ports..."
        x = len(vulnerable_hosts) + 1
        b = 'a' + str(x)  # unique class identifier
        print "[*] checking {0} for open admin ports...".format(host)
        nm.scan(host, str(common_admin_ports))  # nmap scan command
        port = nm[host]['tcp'].keys()  # retrieves tcp port results from scan
        port.sort()  # sorts ports
        y = 0
        for port in port:
            sop = nm[host]['tcp'][port]['state']  # defines port state variable
            if sop == 'open':  # checks to see if status is open
                if b not in vulnerable_hosts:  # checks to see if host already has an object
                    b = VulnerableHost(host)  # creates an object for that host if it doesn't exist
                    vulnerable_hosts.append(b)  # appends vulnerable host to list
                b.add_vulnerable_port(port)
                # print '[+] port : %s >> %s' % (colored(port, 'yellow'), colored(sop, 'green'))
                log_open_port(host, port, sop)
            else:
                y += 1
            if y == len(port):
                print '[!] No open ports found.'
    except Exception as error:
        log_error(error)
    finally:
        connection_lock.release()


# Function runs automatically after the class is instantiated
# Checks to see what vulnerable ports is open for each host
# Then runs the appropriate function to test credentials
# def run(self):
#     for vhost in self.vhosts:
#         print '[*] checking >> {0}'.format(vhost.ip)
#         if 21 in vhost.ports:
#             self.check_ftp(vhost)
#         if 22 in vhost.ports:
#             self.check_ssh(vhost)
#         telnet_ports = [23, 2332]
#         for telnet_port in telnet_ports:
#             if telnet_port in vhost.ports:
#                 self.check_telnet(vhost)
#         http_ports = [8000, 8080, 8081, 8090, 9191, 9443]
#         for http_port in http_ports:
#             if http_port in vhost.ports:
#                 self.http_post_credential_check(vhost, http_port)

# Tries to connect via Telnet with common credentials
# Then it prints the results of the connection attempt
def check_telnet(vulnerable_host):
    try:
        connection_lock.acquire()
        host = vulnerable_host.ip
        print "[*] Testing Telnet connection on {0}...".format(host)
        if 2332 in vulnerable_host.ports:
            port = 2332
        else:
            port = 23
        for user in users:
            x = 0
            while x < len(passwords):
                t = telnetlib.Telnet(host, port, 15)
                t.read_until("ogin: ")
                t.write(user + "\n")
                t.read_until("assword: ")
                t.write(passwords[x] + "\n")
                # t.read_until("OK")
                po = t.read_all()
                print po
                if "successfully" in po:
                    # newcreds = "host={0}, port={1}, user={2}, password={3}, protocol=telnet".format(host,
                    #                                                                                 port, user,
                    #                                                                                 passwords[x])
                    # vulnerable_host.put_credentials(newcreds)
                    protocol = "telnet"
                    log_results(host, port, user, passwords[x], protocol)
                    t.write("quit\n")
                    break
                else:
                    x += 1
                    if x == len(passwords) - 1:
                        print "[!] Password not found."
                        # print "[!] ", e  # prints thrown exception, for debug
                        # TODO: fix looping issue, password found, continues to test passwords
    except Exception as error:
        log_error(error)
    finally:
        connection_lock.release()


# Function checks the FTP service for all users and passwords given
# also tests for anonymous log-ins and does an FTP banner grab
def check_ftp(vulnerable_host):
    try:
        connection_lock.acquire()
        host = vulnerable_host.ip
        print "[*] Testing FTP connection on {0}...".format(host)
        f = FTP(host)
        f.login()
        f.quit()
        fw = f.getwelcome()
        # print "[+] Anonymous FTP connection {0} on {1}.".format(colored("successful", "green"), host)
        # newcreds = "host={0}, protocol=ftp, port=21, user=anon, ,{1}".format(host, fw)
        # vulnerable_host.put_credentials(newcreds)
        port = "21"
        user = "Anonymous"
        password = "none"
        protocol = "FTP"
        log_results(host, port, user, password, protocol)
        print "[+] FTP server responded with {0}".format(fw)
        for user in users:
            x = 0
            while x < len(passwords):
                try:
                    f = FTP()
                    fc = f.connect(host, 21, 1)
                    if fc is True:
                        fw = f.getwelcome()
                        print "[*] FTP server returned {0}".format(fw)
                        f.login(user, passwords[x])
                        f.close()
                        # newcreds = "host={0}, protocol=ftp, port=21, user={1}, password={2}, welcome={3}".format(
                        #     host, user, passwords[x], fw)
                        # vulnerable_host.put_credentials(newcreds)
                        port = "21"
                        protocol = "FTP"
                        log_results(host, port, user, passwords[x], protocol)
                    break
                except Exception as error:
                    log_error(error)
                    x += 1
                    if x == len(passwords):
                        print "[!] Password not found."
    except Exception as error:
        log_error(error)
    finally:
        connection_lock.release()


# Function tests the SSH service with all of the users and passwords given
def check_ssh(vulnerable_host):
    try:
        connection_lock.acquire()
        host = vulnerable_host.ip
        print "[*] Testing SSH service on {0}...".format(host)
        for user in users:
                for password in passwords:
                    try:
                        s = pxssh.pxssh()
                        s.login(host, user, password)
                        # print "[!] Success for SSH! user={0}, password={1}".format(colored(user, 'yellow'),
                        #                                                            colored(password, 'green'))
                        # newcreds = "host={0}, protocol=ssh, port=22, user={1}, password={2}".format(host, user,
                        #                                                                             password)
                        # vulnerable_host.put_credentials(newcreds)
                        port = "22"
                        protocol = "SSH"
                        log_results(host, port, user, password, protocol)
                        s.logout()
                        s.close()
                    except Exception as error:
                        log_error(error)
                        pass
                        # add something here to close openSSH prompt (only occurs when using PyCharm on Linux)
    except Exception as error:
        log_error(error)
    finally:
        connection_lock.release()


# simple banner grab with httplib
def banner_grab(vulnerable_host, http_port):
    try:
        connection_lock.acquire()
        host = vulnerable_host.ip
        print "[*] Grabbing banner from {0}".format(host)
        conn = httplib.HTTPConnection(host, http_port)
        conn.request("GET", "/")
        r1 = conn.getresponse()
        banner_txt = r1.read(1000)
        headers = r1.getheaders()
        print r1.status, r1.reason
        # puts banner into the class instance of the host
        vulnerable_host.put_banner(http_port, banner_txt, r1.status, r1.reason, headers)
    except Exception as error:
        log_error(error)
    finally:
        connection_lock.release()


def http_post_credential_check(vulnerable_host, http_port):
    connection_lock.acquire()
    host = vulnerable_host.ip
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
               "Content-Type": "text/xml","Accept": "application/xml, text/xml, */*; q=0.01",
               "Accept-Language": "en-US,en;q=0.5", "X-Requested-With": "XMLHttpRequest", "Connection": "close"}

    # body_public = '/xml/GetPublic.xml'
    body_connect = '/xml/Connect.xml'

    # xml_public = "xml/Public.xml"
    xml_connect = "xml/Connect.xml"

    method = "HTTP-POST"

    def get_pass_from_xml():
        with open(xml_connect) as f:
            x = f.read()
            m = re.findall("CDATA\[(?P<password>\w*)\]", x)
            if m:
                password = m[0]
                print password
                return password
            else:
                print "nothing found"

    def read_xml(xml_file):
        with open(xml_file, 'r') as f:
            xml = f.read()
            return xml

    def log_results(host, port, user, password, protocol):
        time_now = str(datetime.now())
        print "[*] Recording successful attempt:"
        event = " host={0}, port={1}, user={2}, password={3}, method={4}\n".format(host, port, user, password, protocol)
        print "[*] Password recovered:{0}".format(event)
        with open("recovered_passwords.log", 'a') as f:
            f.write(time_now)
            f.write(event)

    def rec_error(host, port, method, e):
        time_now = str(datetime.now())
        print "[*] Recording error:"
        event = " host={0}, port={1}, method={2}, error={3}\n".format(host, port, method, e)
        print "[*] Error raised:{0}".format(event)
        with open("error.log", 'a') as f:
            f.write(time_now)
            f.write(event)

    # def post_credentials(host, http_port):
    try:
        conn = httplib.HTTPConnection(host, http_port, timeout=25)
        print "[*] Attempting to validate credentials via HTTP-POST..."
        xml = read_xml(xml_connect)
        conn.request("POST", body_connect, xml, headers)
        response = conn.getresponse()
        print response.status, response.reason
        data = response.read()
        if "message='OK'" in data:
            password = get_pass_from_xml()
            log_results(host, http_port, password, method)
        else:
            m = re.findall("message='(?P<error>\w\s/\s\w)'", str(data))
            if m:
                error = m[0]
                print "[*] Server returned: {0}".format(error)
            else:
                print "[*] Server returned: {0}".format(data)
        conn.close()
    except Exception as e:
        m = re.findall("message='(?P<error>\w\s/\s\w)'", str(e))
        if m:
            error = m[0]
            rec_error(host, http_port, method, error)
    finally:
        connection_lock.release()

    # def get_host_list():
    #     host_list_file = sys.argv[1]
    #     with open(host_list_file, 'r') as f:
    #         host_list = f.readlines()
    #         host_list = [i.strip('\r\n') for i in host_list]
    #     return host_list

    # def run_credential_check():
    #     hosts = get_host_list()
    #     for host in hosts:
    #         post_credentials(host)


# Function parses either the default files or user input files
# into the appropriate lists to run the program
def inputs(user_file, password_file, ports):
    # TODO: have ports file read to dictionary, key=port, value=protocol

    input_list = [user_file, password_file, ports]

    global users
    global passwords
    global common_admin_ports

    for x in input_list:
        if x is not None:
            with open(x, 'r') as f:
                if x is user_file:
                    users = f.read().splitlines()
                elif x is password_file:
                    passwords = f.read().splitlines()
                elif x is ports:
                    common_admin_ports = [int(x) for x in f.read().split()]
        else:
            with open('users.txt', 'r') as f:
                users = f.read().splitlines()
            with open('passwords.txt', 'r') as f:
                passwords = f.read().splitlines()
            with open('ports.txt', 'r') as f:
                common_admin_ports = [int(x) for x in f.read().split()]


# Function scans the list or CIDR block to see which hosts are alive
# writes the live hosts to the 'live_hosts' list
# also calculates the percentage of how many hosts are alive
def find_live_hosts(nm, addrs, iL):
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
            live_hosts.append(host)  # adds live hosts to list to scan for open admin ports
        if iL is True:
            global live
            live = len(live_hosts)
            global percentage
            percentage = 100 * (float(live) / float(total))
            print "[+] {0} out of {1} hosts are alive or {2}%".format(live, total, percentage)
    except Exception as error:
        log_error(error)


# splits the list of hosts into two separate lists
# one list is used when creating each thread
# def split_hosts(hosts):
#     half = len(hosts)/2
#     return hosts[:half], hosts[half:]


# Function scans for common admin ports that might be open;
# splits live hosts lists in to multiple lists, generates one threads for each new list
# this speeds up scanning dramatically
def run_admin_scanner():
    threads = []
    print "[*] scanning for open admin ports..."
    try:
        for live_host in live_hosts:
            t = threading.Thread(target=check_admin_ports, args=(live_host, common_admin_ports))
            threads.append(t)
        for thread in threads:
            thread.start()
            thread.join()
    except Exception as error:
        log_error(error)


# Function tests hosts for default credentials on open 'admin' ports
# Utilizes threading to greatly speed up the scanning
def run_thread():
    threads = []
    print "[*] Testing vulnerable host ip addresses..."
    try:
        for vulnerable_host in vulnerable_hosts:
            print '[*] checking >> {0}'.format(vulnerable_host.ip)
            if 21 in vulnerable_host.ports:
                t = threading.Thread(target=check_ftp, args=vulnerable_host)
                threads.append(t)
            if 22 in vulnerable_host.ports:
                t = threading.Thread(target=check_ssh, args=vulnerable_host)
                threads.append(t)
            telnet_ports = [23, 2332]
            for telnet_port in telnet_ports:
                if telnet_port in vulnerable_host.ports:
                    t = threading.Thread(target=check_telnet, args=vulnerable_host)
                    threads.append(t)
            http_ports = [8000, 8080, 8081, 8090, 9191, 9443]
            for http_port in http_ports:
                if http_port in vulnerable_host.ports:
                    t = threading.Thread(target=http_post_credential_check, args=(vulnerable_host, http_port))
                    threads.append(t)
        for thread in threads:
            thread.start()
            thread.join()
    except Exception as error:
        log_error(error)


# Function records all of the results from each instance of the class in to a ?csv? report
# TODO: replace this function, have the class write to file as results are found, better if it crashes
def rec_results(output_file, iL):
    print '[*] recording results...'
    with open(output_file, 'a+') as f:
        if iL is True:
            stats = 'live={0},total={1}\n'.format(live, total)
            f.write(stats)
        for vhost in vulnerable_hosts:
            for port in vhost.ports:
                for x in vhost.banner:
                    if str(port) in x:
                        y = "host={0}, port={1}, status=open, header=yes\n".format(str(vhost.ip), str(port))
                        f.write(y)
                    else:
                        y = "host={0}, port={1}, status=open, header=no\n".format(str(vhost.ip), str(port))
                        f.write(y)
        headers_creds = 'host,protocol,port,user,password,misc\n'
        f.write(headers_creds)
        for vhost in vulnerable_hosts:
            # print vhost.credentials  # returns correct values
            x = str(vhost.p_creds).strip("['']") + '\n'  # assigns credentials to x, correctly
            f.write(x)  # writes x to file, also correctly
            bfile = 'banners_' + output_file
            with open(bfile, 'a+') as b:
                for x in vhost.banner:
                    y = str(vhost.ip) + ' ' + str(x)
                    b.write(y)


def log_open_port(host, port, status):
    time_now = datetime.now()
    event = " host={0}, port={1}, status={2}\n".format(host, port, status)
    print "[*] Open port found:{0}".format(event)
    with open("open_ports.log", 'a') as f:
        f.write(str(time_now))
        f.write(event)


def log_results(host, port, user, password, protocol):
    time_now = str(datetime.now())
    print "[*] Recording successful attempt:"
    event = " host={0}, port={1}, user={2}, password={3}, protocol={4}\n".format(host, port, user, password, protocol)
    print "[*] Password recovered:{0}".format(event)
    with open("recovered_passwords.log", 'a') as f:
        f.write(time_now)
        f.write(event)


# Logs any Exception or error that is thrown by the program.
def log_error(error):
    time_now = datetime.now()
    log_error_message = str(time_now) + ":" + str(error) + "\n"
    with open('error.log', 'a') as f:
        f.write(log_error_message)
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
    parser.add_option('-s', dest='services', type='string', help='services to scan, all by default')

    (options, args) = parser.parse_args()
    ifile = options.ifile
    cidr = options.cidr
    ofile = options.ofile
    ufile = options.ufile
    pfile = options.pfile
    ports = options.ports

    # Reads users, passwords, and ports files to generate lists to test.
    inputs(ufile, pfile, ports)

    # Validates the input options.
    if ifile is not None and cidr is not None:
        print "[!] Cannot have two input options!"
        print parser.usage
        exit(0)
    elif ifile is None and cidr is None:
        print "[!] Must define something to scan!"
        print parser.usage
        exit(0)
    else:
        if ifile is not None:  # checks if input is a file
            addrs = ifile
            iL = True  # iL is the switch for NMAP to read from file
            # Calculates total hosts to generate statistics
            with open(addrs, 'r') as f:
                total_hosts = f.readlines()
                global total
                total = len(total_hosts)
        else:
            addrs = cidr
            iL = False
        try:
            find_live_hosts(nm, addrs, iL)  # Uses NMAP ping scan to check for live hosts
            # TODO: add option to disable port scan and just test ports listed in file.
            run_admin_scanner()  # Checks for open admin ports, defined in file.
            run_thread()  # Starts the threads to check the open ports for default credentials.
        except Exception as error:
            log_error(error)
        finally:
            # Writes to file if the output switch is given.
            if ofile is not None:
                rec_results(ofile, iL)
            print datetime.now() - start_time  # Calculates run time for the program.


if __name__ == "__main__":
    main()
