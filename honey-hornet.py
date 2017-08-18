#! /usr/bin/env python

import telnetlib
from ftplib import FTP
import optparse
import threading
from threading import Thread, BoundedSemaphore
from datetime import datetime
import httplib
import re
from termcolor import colored
from pexpect import pxssh
import nmap


MAX_CONNECTIONS = 20
CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTIONS)

live_hosts = []  # writes live hosts that are found here
vulnerable_hosts = []  # hosts that have open admin ports


class VulnerableHost(object):
    """ defines a class for each live host with an open admin port
    saves ports, credentials and banner grabs, defines hosts ip address
    creates ports list, creates a credentials list,
    creates a list to hold banners, assigns itself the vulnerable IP """
    def __init__(self, ipaddr):
        self.ports = []
        self.credentials = []
        self.banner = []
        self.ip = ipaddr

    def add_vulnerable_port(self, port):
        """ function adds open admin port to list """
        self.ports.append(port)

    def put_credentials(self, newcreds):
        """ records default credentials of an open admin port """
        self.credentials.append(newcreds)

    def put_banner(self, port, banner_txt, status, reason, headers):
        """ adds port, banner to banner list """
        self.banner.append(':{0} {1} {2} {3}\n{4}\n'.format(port, status, reason, banner_txt, headers))


def check_admin_ports(live_host, common_admin_ports):
    """Scans a live_host for any open common admin ports.
    If an open port is found, it instantiates a class for that host
    and records all the open ports
    Tests all live host for open 'admin' ports
    """
    try:
        CONNECTION_LOCK.acquire()
        host = live_host
        scanner = nmap.PortScanner()  # defines port scanner function
        print "[*] scanning for open admin ports..."
        counter = len(vulnerable_hosts) + 1
        host_id = 'a' + str(counter)  # unique class identifier
        print "[*] checking {0} for open admin ports...".format(host)
        scanner.scan(host, str(common_admin_ports))  # nmap scan command
        ports = scanner[host]['tcp'].keys()  # retrieves tcp port results from scan
        ports.sort()  # sorts ports
        counter2 = 0
        for port in ports:
            sop = scanner[host]['tcp'][port]['state']  # defines port state variable
            if sop == 'open':  # checks to see if status is open
                if host_id not in vulnerable_hosts:  # checks to see if host already has an object
                    new_host = VulnerableHost(host)  # creates new object
                    vulnerable_hosts.append(new_host)  # appends vulnerable host to list
                new_host.add_vulnerable_port(port)
                # print '[+] port : %s >> %s' % (colored(port, 'yellow'), colored(sop, 'green'))
                log_open_port(host, port, sop)
            else:
                counter2 += 1
            if counter2 == len(ports):
                print '[!] No open ports found.'
    except Exception as error:
        log_error(error)
    finally:
        CONNECTION_LOCK.release()


def check_telnet(vulnerable_host):
    """ Tries to connect via Telnet with common credentials
    Then it prints the results of the connection attempt
    Due to the way TELNETLIB works and the different implementations of telnet
    This is fairly inefficient way to test credentials
    Really needs to be customized based on the telnet implementation
    Web-based credential testing is much better and more standardized
    """
    try:
        CONNECTION_LOCK.acquire()
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
                po = t.read_all()
                print po
                if "successfully" in po:
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
        CONNECTION_LOCK.release()


def check_ftp_anon(vulnerable_host):
    """ Function checks the FTP service for anonymous log-ins and does an FTP banner grab """
    try:
        CONNECTION_LOCK.acquire()
        host = vulnerable_host.ip
        print "[*] Testing FTP connection on {0}...".format(host)
        ftp_conn = FTP(host)
        ftp_conn.login()
        ftp_conn.quit()
        ftp_welcome = ftp_conn.getwelcome()
        port = "21"
        user = "Anonymous"
        password = "none"
        protocol = "FTP"
        log_results(host, port, user, password, protocol)
        print "[+] FTP server responded with {0}".format(ftp_welcome)
    except Exception as error:
        log_error(error)
    finally:
        CONNECTION_LOCK.release()


def check_ftp(vulnerable_host):
    """ Checks the host for FTP connection using username and password combinations """
    try:
        CONNECTION_LOCK.acquire()
        host = vulnerable_host.ip
        print "[*] Testing FTP connection on {0}...".format(host)
        for user in users:
            password_counter = 0
            while password_counter < len(passwords):
                try:
                    ftp_conn = FTP()
                    if ftp_conn.connect(host, 21, 1):
                        ftp_welcome = ftp_conn.getwelcome()
                        print "[*] FTP server returned {0}".format(ftp_welcome)
                        ftp_conn.login(user, passwords[password_counter])
                        ftp_conn.close()
                        port = "21"
                        protocol = "FTP"
                        log_results(host, port, user, passwords[password_counter], protocol)
                    break
                except Exception as error:
                    log_error(error)
                    password_counter += 1
                    if password_counter == len(passwords):
                        print "[!] Password not found."
    except Exception as error:
        log_error(error)
    finally:
        CONNECTION_LOCK.release()


def check_ssh(vulnerable_host):
    """ Function tests the SSH service with all of the users and passwords given """
    try:
        CONNECTION_LOCK.acquire()
        host = vulnerable_host.ip
        print "[*] Testing SSH service on {0}...".format(host)
        for user in users:
            for password in passwords:
                ssh_conn = pxssh.pxssh()
                ssh_conn.login(host, user, password)
                port = "22"
                protocol = "SSH"
                log_results(host, port, user, password, protocol)
                ssh_conn.logout()
                ssh_conn.close()
    except Exception as error:
        log_error(error)
    finally:
        CONNECTION_LOCK.release()


def banner_grab(vulnerable_host, http_port):
    """ simple banner grab with HTTPLIB """
    try:
        CONNECTION_LOCK.acquire()
        host = vulnerable_host.ip
        print "[*] Grabbing banner from {0}".format(host)
        conn = httplib.HTTPConnection(host, http_port)
        conn.request("GET", "/")
        http_r1 = conn.getresponse()
        banner_txt = http_r1.read(1000)
        headers = http_r1.getheaders()
        print http_r1.status, http_r1.reason
        # puts banner into the class instance of the host
        vulnerable_host.put_banner(http_port, banner_txt, http_r1.status, http_r1.reason, headers)
    except Exception as error:
        log_error(error)
    finally:
        CONNECTION_LOCK.release()


def http_post_credential_check(vulnerable_host, http_port):
    """ Tests for default credentials against an Web-based Authentication
    Reads and POSTs data via XML files.
    This only handles one specific type of Web-based Authentication at this time.
    """
    CONNECTION_LOCK.acquire()
    host = vulnerable_host.ip
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
               "Content-Type": "text/xml",
               "Accept": "application/xml, text/xml, */*; q=0.01",
               "Accept-Language": "en-US,en;q=0.5",
               "X-Requested-With": "XMLHttpRequest",
               "Connection": "close"}

    xml_connect = "xml/Connect.xml"

    method = "HTTP-POST"

    def get_pass_from_xml():
        """ Extracts the password from the xml file. Uses this when recording the results """
        with open(xml_connect) as f:
            x = f.read()
            m = re.findall(r"CDATA\[(?P<password>\w*)\]", x)
            if m:
                password = m[0]
                print password
                return password
            else:
                print "nothing found"

    def read_xml(xml_file):
        """ Reads the XML file to put in body of request """
        with open(xml_file, 'r') as f:
            xml = f.read()
            return xml

    def log_results(host, port, user, password, protocol):
        """ Logs successful authentication requests """
        time_now = str(datetime.now())
        print "[*] Recording successful attempt:"
        event = " host={0}, port={1}, user={2}, password={3}, method={4}\n".format(host, port,
                                                                                   user, password,
                                                                                   protocol)
        print "[*] Password recovered:{0}".format(event)
        with open("recovered_passwords.log", 'a') as f:
            f.write(time_now)
            f.write(event)

    def rec_error(host, port, method, error):
        """ Records any errors in the Web-based authentication thread. """
        time_now = str(datetime.now())
        print "[*] Recording error:"
        event = " host={0}, port={1}, method={2}, error={3}\n".format(host, port, method, error)
        print "[*] Error raised:{0}".format(event)
        with open("error.log", 'a') as f:
            f.write(time_now)
            f.write(event)

    # Tries to connect to host via HTTP-POST w/ the XML authentication in the body of the request.
    # Uses Regular Expressions to extract errors for debugging/tuning the program.
    try:
        conn = httplib.HTTPConnection(host, http_port, timeout=25)
        print "[*] Attempting to validate credentials via HTTP-POST..."
        xml = read_xml(xml_connect)
        # should be able to remove the "body_connect" (xml duplicate)
        conn.request("POST", body_connect, xml, headers)
        response = conn.getresponse()
        print response.status, response.reason
        data = response.read()
        if "message='OK'" in data:
            password = get_pass_from_xml()
            protocol = "WEB-AUTH"
            log_results(host, http_port, password, method, protocol)
        else:
            error_msg = re.findall(r"message='(?P<error>\w\s/\s\w)'", str(data))
            if error_msg:
                error = error_msg[0]
                print "[*] Server returned: {0}".format(error)
            else:
                print "[*] Server returned: {0}".format(data)
        conn.close()
    except Exception as error:
        error_msg = re.findall("message='(?P<error>.*)'", str(error))
        if error_msg:
            error = error_msg[0]
            rec_error(host, http_port, method, error)
    finally:
        CONNECTION_LOCK.release()

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


def inputs(user_file, password_file, ports):
    """ Function parses either the default files or user input files
    into the appropriate lists to run the program
    """
    # TODO: have ports file read to dictionary, key=port, value=protocol

    input_list = [user_file, password_file, ports]

    global users
    global passwords
    global common_admin_ports

    for thing in input_list:
        if thing is not None:
            with open(thing, 'r') as input_file:
                if thing is user_file:
                    users = input_file.read().splitlines()
                elif thing is password_file:
                    passwords = input_file.read().splitlines()
                elif thing is ports:
                    common_admin_ports = [int(x) for x in input_file.read().split()]
        else:
            with open('users.txt', 'r') as user_file:
                users = user_file.read().splitlines()
            with open('passwords.txt', 'r') as password_file:
                passwords = password_file.read().splitlines()
            with open('ports.txt', 'r') as ports_file:
                common_admin_ports = [int(x) for x in ports_file.read().split()]


def find_live_hosts(addrs, iL, scanner):
    """ Function scans the list or CIDR block to see which hosts are alive
    writes the live hosts to the 'live_hosts' list
    also calculates the percentage of how many hosts are alive
    """
    print "[*] scanning for live hosts..."
    try:
        # scanner = nmap.PortScanner()
        if iL is False:
            scanner.scan(hosts=addrs, arguments='-sn')  # ping scan to check for live hosts
        else:
            scanner.scan(arguments='-sn -iL ' + addrs)
        hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
        # prints the hosts that are alive
        for host, status in hosts_list:
            print '[+] {0} is {1}'.format(colored(host, 'yellow'), colored(status, 'green'))
            live_hosts.append(host)  # adds live hosts to list to scan for open admin ports
        if iL is True:
            global live
            live = len(live_hosts)
            global percentage
            percentage = 100 * (float(live) / float(total))
            print "[+] {0} out of {1} hosts are alive or {2}%".format(live, total, percentage)
            with open("open_ports.log", 'a') as f:
                log_totals = "{0}\{1} = {2}%".format(live, total, percentage)
                f.write(log_totals)
    except Exception as error:
        raise
        # log_error(error)


def run_admin_scanner():
    """ Function scans for common admin ports that might be open;
    Starts a thread for each host dramatically speeding up the scan
    """
    threads = []
    print "[*] scanning for open admin ports..."
    try:
        for live_host in live_hosts:
            new_thread = threading.Thread(target=check_admin_ports, args=(live_host, common_admin_ports))
            threads.append(new_thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    except Exception as error:
        log_error(error)


def run_credential_test():
    """ Function tests hosts for default credentials on open 'admin' ports
    Utilizes threading to greatly speed up the scanning
    """
    threads = []
    print "[*] Testing vulnerable host ip addresses..."
    try:
        for vulnerable_host in vulnerable_hosts:
            print '[*] checking >> {0}'.format(vulnerable_host.ip)
            if 21 in vulnerable_host.ports:
                t = threading.Thread(target=check_ftp_anon, args=vulnerable_host)
                threads.append(t)
                t1 = threading.Thread(target=check_ftp, args=vulnerable_host)
                threads.append(t1)
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


def log_open_port(host, port, status):
    """ Logs any host with an open port to a file. """
    time_now = datetime.now()
    event = " host='{0}'', port={1}, status='{2}'\n".format(host, port, status)
    print "[*] Open port found:{0}".format(event)
    with open("open_ports.log", 'a') as f:
        f.write(str(time_now))
        f.write(event)


def log_results(host, port, user, password, protocol):
    """ Logs credentials that are successfully recovered. """
    time_now = str(datetime.now())
    print "[*] Recording successful attempt:"
    event = " host='{0}', port={1}, user='{2}', password='{3}', protocol='{4}'\n".format(host, port, user, password, protocol)
    print "[*] Password recovered:{0}".format(event)
    with open("recovered_passwords.log", 'a') as f:
        f.write(time_now)
        f.write(event)


def log_error(error):
    """ Logs any Exception or error that is thrown by the program. """
    time_now = datetime.now()
    log_error_message = str(time_now) + ":" + str(error) + "\n"
    with open('error.log', 'a') as f:
        f.write(log_error_message)
        print "[*] Error logged: {0}".format(error)


def main():
    """ Main program """
    start_time = datetime.now()

    parser = optparse.OptionParser('usage: %prog <scan type> <targets> <options>)
    parser.add_option('-i', dest='ifile', type='string', help='import IP addresses from file, cannot be used with -c')
    parser.add_option('-c', dest='cidr', type='string', help='cidr block or localhost, cannot be used with -i')
    parser.add_option('-u', dest='ufile', type='string', help='imports users from file; else: uses default list')
    parser.add_option('-p', dest='pfile', type='string', help='imports passwords from file; else: uses default list')
    parser.add_option('-a', dest='ports', type='string', help='import ports from file')
    parser.add_option('-s', dest='scans', type='string', help='scan types to use, 1=port scan 2=credential scan 3=both')

    (options, args) = parser.parse_args()
    ifile = options.ifile
    cidr = options.cidr
    ufile = options.ufile
    pfile = options.pfile
    ports = options.ports
    scans = options.scans

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
            scanner = nmap.PortScanner()
            if scans == '1':
                find_live_hosts(addrs, iL, scanner)  # Uses NMAP ping scan to check for live hosts
                run_admin_scanner()  # Checks for open admin ports, defined in file
            elif scans == '2':
                find_live_hosts(addrs, iL, scanner)
                run_credential_test()  # Starts the threads to check the open ports for default credentials.
            elif scans == '3':
                find_live_hosts(addrs, iL, scanner)
                run_admin_scanner()
                run_credential_test()
            else:
                print "[!] Please define a scan type!"
                print parser.usage
                exit(0)
        except Exception as error:
            raise
            log_error(error)
        finally:
            # Writes to file if the output switch is given.
            # if ofile is not None:
            #     rec_results(ofile, iL)
            print datetime.now() - start_time  # Calculates run time for the program.


if __name__ == "__main__":
    main()
