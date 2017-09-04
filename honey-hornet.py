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
import time
import itertools
import yaml


class HoneyHornet:

    vulnerable_hosts = []  # hosts that have open admin ports

    def __init__(self):
        self.live_hosts = []  # writes live hosts that are found here
        MAX_CONNECTIONS = 20
        self.CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTIONS)
        self.TIMER_DELAY = 3
        self.users = []
        self.passwords = []
        self.banner = False
        with open('config.yml', 'r') as cfg_file:
            self.config = yaml.load(cfg_file)
            # print self.config
            # print self.config['users']

    def add_banner_grab(self, banner):
        if banner == '1':
            self.banner = True
        else:
            self.banner = False

    def log_open_port(self, host, port, status):
        """ Logs any host with an open port to a file. """
        time_now = datetime.now()
        event = " host={0}, port={1}, status='{2}'\n".format(colored(host, 'red'), colored(port, 'red'),
                                                               colored(status, 'green'))
        print "[*] Open port found:{0}".format(event)
        with open("open_ports.log", 'a') as log_file:
            log_file.write(str(time_now))
            log_file.write(event)

    def log_results(self, host, port, user, password, protocol):
        """ Logs credentials that are successfully recovered. """
        time_now = str(datetime.now())
        print "[*] Recording successful attempt:"
        event = " host={0}, port={1}, user='{2}', password='{3}', protocol='{4}'\n".format(host, port, user, password,
                                                                                             protocol)
        print "[*] Password recovered:{0}".format(event)
        with open("recovered_passwords.log", 'a') as log_file:
            log_file.write(time_now)
            log_file.write(event)

    def log_error(self, error):
        """ Logs any Exception or error that is thrown by the program. """
        time_now = datetime.now()
        log_error_message = str(time_now) + ":" + str(error) + "\n"
        with open('error.log', 'a') as f:
            f.write(log_error_message)
            print "[*] Error logged: {0}".format(error)

    # TODO: Deprecated, delete.
    # def build_ports_list(self, ports):
    #     """ Reads a file to build a list of ports to scan. """
    #     if ports is None:
    #         ports = "ports.txt"
    #     with open(ports, 'r') as ports_file:
    #         ports_list = [int(x) for x in ports_file.read().split()]
    #         return ports_list

    # TODO: Deprecated, delete.
    # def find_live_hosts(self, target_list, iL):
    #     """ Function scans the list or CIDR block to see which hosts are alive
    #     writes the live hosts to the 'live_hosts' list
    #     also calculates the percentage of how many hosts are alive
    #     """
    #     print "[*] scanning for live hosts..."
    #     try:
    #         scanner = nmap.PortScanner()
    #         if iL is False:
    #             scanner.scan(hosts=target_list, arguments='-sn')  # ping scan to check for live hosts
    #         else:
    #             scanner.scan(arguments='-sn -iL ' + str(target_list))
    #         hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
    #         # prints the hosts that are alive
    #         for host, status in hosts_list:
    #             print '[+] {0} is {1}'.format(colored(host, 'yellow'), colored(status, 'green'))
    #             self.live_hosts.append(host)  # adds live hosts to list to scan for open admin ports
    #         if iL is True:
    #             live = len(self.live_hosts)
    #             percentage = 100 * (float(live) / float(total))
    #             print "[+] {0} out of {1} hosts are alive or {2}%".format(live, total, percentage)
    #             with open("open_ports.log", 'a') as log_file:
    #                 new_log = "##############  NEW SCAN  ##############\n"
    #                 log_file.write(new_log)
    #                 log_totals = "{0}\{1} = {2}%\n".format(live, total, percentage)
    #                 log_file.write(log_totals)
    #     except Exception as error:
    #         self.log_error(error)

    def check_admin_ports(self, target_list, ports_to_scan):
        """Scans a live_host for any open common admin ports.
        If an open port is found, it instantiates a class for that host
        and records all the open ports
        Tests all live host for open 'admin' ports

        Changed to let Nmap handling the threading.
        Had implemented threading, but threading Nmap, which is threaded seems to add huge complications.
        New implementation is very fast and almost no issues.
        Ports list as argument needed to have the whitespace stripped between each port.
        """
        # TODO: Add up percentage like in live hosts above.
        try:
            scanner = nmap.PortScanner()  # defines port scanner function
            print "[*] checking for open admin ports..."
            targets = '-iL ' + str(target_list).strip('[]')
            ports = ' -p ' + str(ports_to_scan).strip('[]').replace(' ', '')
            scanner.scan(hosts=targets, arguments=ports)  # Nmap scan command
            hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
            for host, status in hosts_list:
                ports = scanner[host]['tcp'].keys()  # retrieves tcp port results from scan
                if ports:
                    ports.sort()  # sorts ports
                    new_host = VulnerableHost(host)  # creates new object
                    self.vulnerable_hosts.append(new_host)
                    for port in ports:
                        port_state = scanner[host]['tcp'][port]['state']  # defines port state variable
                        if port_state == 'open':  # checks to see if status is open
                            new_host.add_vulnerable_port(port)
                            self.log_open_port(host, port, port_state)
        except Exception as error:
            self.log_error(error)

    # TODO: Deprecated, delete.
    # def run_admin_scanner(self, ports):
    #     """ Function scans for common admin ports that might be open;
    #     Starts a thread for each host dramatically speeding up the scan
    #     """
    #     threads = []
    #     ports_list = self.build_ports_list(ports)
    #     print "[*] scanning for open admin ports..."
    #     try:
    #         for live_host in self.live_hosts:
    #             self.check_admin_ports(live_host, ports_list)
    #             new_thread = threading.Thread(target=self.check_admin_ports, args=(live_host, ports_list))
    #             threads.append(new_thread)
    #         for thread in threads:
    #             thread.start()
    #         for thread in threads:
    #             thread.join()
    #     except KeyboardInterrupt:
    #         exit(0)
    #     except Exception as error:
    #         self.log_error(error)


class VulnerableHost(HoneyHornet):
    """ defines a class for each live host with an open admin port
    saves ports, credentials and banner grabs, defines hosts ip address
    creates ports list, creates a credentials list,
    creates a list to hold banners, assigns itself the vulnerable IP """
    def __init__(self, ipaddr):
        HoneyHornet.__init__(self)
        self.ports = []
        self.credentials = []
        self.banner = []
        self.ip = ipaddr

    def log_open_port(self, host, port, status):
        """ Logs any host with an open port to a file. """
        time_now = datetime.now()
        event = " host='{0}', port={1}, status='{2}'\n".format(host, port, status)
        print "[*] Open port found:{0}".format(event)
        with open("open_ports.log", 'a') as log_file:
            log_file.write(str(time_now))
            log_file.write(event)

    def log_results(self, host, port, user, password, protocol):
        """ Logs credentials that are successfully recovered. """
        time_now = str(datetime.now())
        print "[*] Recording successful attempt:"
        event = " host='{0}', port={1}, user='{2}', password='{3}', protocol='{4}'\n".format(host, port, user, password,
                                                                                             protocol)
        print "[*] Password recovered:{0}".format(event)
        with open("recovered_passwords.log", 'a') as log_file:
            log_file.write(time_now)
            log_file.write(event)

    def log_error(self, error):
        """ Logs any Exception or error that is thrown by the program. """
        time_now = datetime.now()
        log_error_message = str(time_now) + ":" + str(error) + "\n"
        with open('error.log', 'a') as f:
            f.write(log_error_message)
            print "[*] Error logged: {0}".format(error)

    def add_vulnerable_port(self, port):
        """ function adds open admin port to list """
        self.ports.append(port)

    def put_credentials(self, new_credentials):
        """ records default credentials of an open admin port """
        self.credentials.append(new_credentials)

    def put_banner(self, port, banner_txt, status, reason, headers):
        """ adds port, banner to banner list """
        self.banner.append(':{0} {1} {2} {3}\n{4}\n'.format(port, status, reason, banner_txt, headers))


class CheckCredentials(VulnerableHost):
    def __init__(self):
        HoneyHornet.__init__(self)
        # VulnerableHost.__init__(self)
        self.http_ports = [8000, 8080, 8081, 8090, 9191, 9443]
        self.telnet_ports = [23, 2332]

    def build_credentials(self):
        """ Function parses either the default files or user input files
        into the appropriate lists to run the program
        """
        # file_list = [user_file, password_file]
        # TODO: finish fixing credentials using the list(itertools()) for user input
        try:
            # for thing in file_list:
            #     if thing is not None:
            #         with open(thing, 'r') as input_file:
            #             if thing is user_file:
            #                 users = input_file.read().splitlines()
            #             elif thing is password_file:
            #                 passwords = input_file.read().splitlines()
            #     else:
            #         with open('users.txt', 'r') as user_file:
            #             users = user_file.read().splitlines()
            #         with open('passwords.txt', 'r') as password_file:
            #             passwords = password_file.read().splitlines()
            users = self.config['users']
            passwords = self.config['passwords']
            credentials = list(itertools.product(users, passwords))
            return credentials
        except Exception as error:
            self.log_error(error)
            return False

    def check_telnet(self, vulnerable_host, port, credentials):
        """ Tries to connect via Telnet with common credentials
        Then it prints the results of the connection attempt
        Due to the way TELNETLIB works and the different implementations of telnet
        This is fairly inefficient way to test credentials
        Really needs to be customized based on the telnet implementation
        Web-based credential testing is much better and more standardized

        UPDATE: Found that using a time.sleep() pause is a much more effective way of
        inputting credentials when testing. Generally, an "OK" response is received
        almost immediately when the correct credentials are supplied. When the wrong
        credentials are supplied, the response is much more delayed. A 3 second timeout
        has been effective.
        """
        try:
            self.CONNECTION_LOCK.acquire()
            for credential in credentials:
                host = vulnerable_host.ip
                user = credential[0]
                password = credential[1]
                print "[*] Testing Telnet connection on {0}...".format(host)
                # print "[*] username: {0} password: {1} port: {2}".format(user, password, port)
                t = telnetlib.Telnet(host, port, 15)
                time.sleep(self.TIMER_DELAY)
                t.write(user + "\r\n")
                time.sleep(self.TIMER_DELAY)
                t.write(password + "\r\n")
                time.sleep(self.TIMER_DELAY)
                server_response = t.read_very_eager()
                # print server_response
                if "OK" in server_response:
                    protocol = "telnet"
                    self.log_results(host, port, user, password, protocol)
                    t.close()
                    return True
                elif "incorrect" in server_response:
                    self.log_error("Password incorrect.")
                    t.close()
                    return False
                else:
                    t.close()
                    return False
        except Exception as error:
            self.log_error(error)
            return False
        finally:
            self.CONNECTION_LOCK.release()

    def check_ftp_anon(self, vulnerable_host):
        """ Function checks the FTP service for anonymous log-ins and does an FTP banner grab """
        try:
            self.CONNECTION_LOCK.acquire()
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
            self.log_results(host, port, user, password, protocol)
            print "[+] FTP server responded with {0}".format(ftp_welcome)
            return True
        except Exception as error:
            self.log_error(error)
            return False
        finally:
            self.CONNECTION_LOCK.release()

    def check_ftp(self, vulnerable_host, credentials):
        """ Checks the host for FTP connection using username and password combinations """
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            for credential in credentials:
                user = credential[0]
                password = credential[1]
                print "[*] Testing FTP connection on {0}...".format(host)
                ftp_conn = FTP()
                if ftp_conn.connect(host, 21, 1):
                    ftp_welcome = ftp_conn.getwelcome()
                    print "[*] FTP server returned {0}".format(ftp_welcome)
                    ftp_conn.login(user, password)
                    ftp_conn.close()
                    port = "21"
                    protocol = "FTP"
                    self.log_results(host, port, user, password, protocol)
                break
        except Exception as error:
            self.log_error(error)
        finally:
            self.CONNECTION_LOCK.release()

    def check_ssh(self, vulnerable_host, credentials):
        """ Function tests the SSH service with all of the users and passwords given """
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            print "[*] Testing SSH service on {0}...".format(host)
            for credential in credentials:
                user = credential[0]
                password = credential[1]
                ssh_conn = pxssh.pxssh()
                # ssh_conn = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "-oHostKeyAlgorithms": "+ssh-dss"})
                ssh_conn.login(host, user, password)
                port = "22"
                protocol = "SSH"
                self.log_results(host, port, user, password, protocol)
                ssh_conn.logout()
                ssh_conn.close()
        except pxssh.ExceptionPxssh as error:
            self.log_error(error)
        finally:
            self.CONNECTION_LOCK.release()

    def banner_grab(self, vulnerable_host):
        """ simple banner grab with HTTPLIB """
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            print "[*] Grabbing banner from {0}".format(host)
            ports_to_check = set(self.http_ports) & set(vulnerable_host.ports)
            for http_port in ports_to_check:
                conn = httplib.HTTPConnection(host, http_port)
                conn.request("GET", "/")
                http_r1 = conn.getresponse()
                banner_txt = http_r1.read(1000)
                headers = http_r1.getheaders()
                print http_r1.status, http_r1.reason
                # puts banner into the class instance of the host
                vulnerable_host.put_banner(http_port, banner_txt, http_r1.status, http_r1.reason, headers)
                with open('banner_grabs.log') as banner_log:
                    banner_to_log = "host={0}, http_port={1},\nheaders={2},\nbanner={3}\n".format(host, http_port,
                                                                                                  headers, banner_txt)
                    banner_log.write(banner_to_log)
        except Exception as error:
            self.log_error(error)
        finally:
            self.CONNECTION_LOCK.release()

    def http_post_xml(self, vulnerable_host):
        """ Tests for default credentials against an Web-based Authentication
        Reads and POSTs data via XML files.
        This only handles one specific type of Web-based Authentication at this time.
        """
        self.CONNECTION_LOCK.acquire()
        host = vulnerable_host.ip
        ports_to_check = set(self.http_ports) & set(vulnerable_host.ports)
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

        # Tries to connect to host via HTTP-POST w/ the XML authentication in the body of the request.
        # Uses Regular Expressions to extract errors for debugging/tuning the program.
        try:
            for http_port in ports_to_check:
                conn = httplib.HTTPConnection(host, http_port, timeout=25)
                print "[*] Attempting to validate credentials via HTTP-POST..."
                xml = read_xml(xml_connect)
                # should be able to remove the "body_connect" (xml duplicate)
                conn.request("POST", "/", xml, headers)
                response = conn.getresponse()
                print response.status, response.reason
                data = response.read()
                if "message='OK'" in data:
                    password = get_pass_from_xml()
                    protocol = "WEB-AUTH"
                    self.log_results(host, http_port, password, method, protocol)
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
                error_msg = host, http_port, method, error
                self.log_error(error_msg)
        finally:
            self.CONNECTION_LOCK.release()

    def run_credential_test(self, hosts_to_check, ufile, pfile):
        """ Function tests hosts for default credentials on open 'admin' ports
        Utilizes threading to greatly speed up the scanning
        """
        credentials_to_check = self.build_credentials()
        threads = []
        print "[*] Testing vulnerable host ip addresses..."
        try:
            for vulnerable_host in hosts_to_check:
                print '[*] checking >> {0}'.format(vulnerable_host.ip)
                if 21 in vulnerable_host.ports:
                    t0 = threading.Thread(target=self.check_ftp_anon, args=(vulnerable_host, ))
                    t1 = threading.Thread(target=self.check_ftp, args=(vulnerable_host, credentials_to_check))
                    threads.append(t0)
                    threads.append(t1)
                if 22 in vulnerable_host.ports:
                    t = threading.Thread(target=self.check_ssh, args=(vulnerable_host, credentials_to_check))
                    threads.append(t)
                ports_to_check = set(self.telnet_ports) & set(vulnerable_host.ports)
                if ports_to_check:
                    for port in ports_to_check:
                        t = threading.Thread(target=self.check_telnet, args=(vulnerable_host, port, credentials_to_check))
                        threads.append(t)
                if set(self.http_ports) & set(vulnerable_host.ports):
                    t0 = threading.Thread(target=self.http_post_xml, args=(vulnerable_host,))
                    threads.append(t0)
                    if self.banner is True:
                        t1 = threading.Thread(target=self.banner_grab, args=(vulnerable_host, ))
                        threads.append(t1)
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            exit(0)
        except Exception as error:
            self.log_error(error)


def main():
    """ Main program """
    start_time = datetime.now()
    # TODO: add resume option (read from file)

    hh = HoneyHornet()

    # if banner is not None:
    #     hh.add_banner_grab(banner)

    target_hosts = hh.config['targets']
    ports_to_scan = hh.config['ports']
    scan_type = str(hh.config['scanType']).strip('['']')

    try:
        if scan_type == '1':
            print "[*] Running in port scanner mode..."
            hh.check_admin_ports(target_hosts, ports_to_scan)
        elif scan_type == '2':
            print "[*] Running in credential check mode..."
            hh.check_admin_ports(target_hosts, ports_to_scan)
            hosts_to_check = hh.vulnerable_hosts
            CheckCredentials().run_credential_test(hosts_to_check)
        # elif scan_type == 3:
        #     hh.find_live_hosts(target_hosts, iL)
        #     hh.run_admin_scanner(ports)
        #     hh.check_admin_ports(target_hosts, ports_to_scan)
        #     hosts_to_check = hh.vulnerable_hosts
        #     CheckCredentials().run_credential_test(hosts_to_check, ufile, pfile)
        else:
            print "[!] Please define a scan type!"
            exit(0)
    except KeyboardInterrupt:
        exit(0)
    except Exception as error:
        hh.log_error(error)
    finally:
        print datetime.now() - start_time  # Calculates run time for the program.


if __name__ == "__main__":
    main()
