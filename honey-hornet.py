#! /usr/bin/env python

import telnetlib
from ftplib import FTP
import threading
from threading import BoundedSemaphore
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
    """ Main Honey Hornet Class

    Holds all vulnerable hosts that are identified by the NMAP scan.
    Holds all the default variables for the program: max thread connections, timer delay for login testing, users to
    test, passwords to test, whether or not to have a verbose output and whether or not to grab a banner when connecting
    to an open port.

    Loads user-defined configurations from YAML config file. Default file = $HONEY_HORNET_HOME$/config.yml

    Functions that handle two types of results logging:
        1. log_open_ports() logs any open port found during the check_admin_ports() scan.
        2. log_results() logs any credentials from a successful login attempt.
    Functions that handle two types of error logging:
        1. log_error() logs general errors with setting up and running the program.
        2. log_service_error() logs errors specific to testing credentials through a specific service.

    The function check_admin_ports() runs an NMAP scan for the targets and ports defined in the YAML config file. It is
    a simple TCP SYN scan (half open) that checks to see if the port is open or not. It does not do service discovery.
    Right now the program tests service by port default, e.g. if port 23 is open, it automatically runs a Telnet
    service credential check without testing to verify that Telnet is running on that port.

    For each host/target that is found with an open port, check_admin_ports() instantiates an object of the
    VulnerableHost class.
    """

    vulnerable_hosts = []  # hosts that have open admin ports

    def __init__(self):
        self.live_hosts = []  # writes live hosts that are found here
        MAX_CONNECTIONS = 20  # max threads that can be created
        self.CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTIONS)
        self.TIMER_DELAY = 3  # timer delay used for Telnet testing
        self.users = []  # users that will be tested
        self.passwords = []  # passwords to be tested
        self.verbose = False  # if there will be a verbose output, default=False
        self.banner = False  # if we should do a banner grab, default=False
        # TODO: add the ability for a user to define custom YAML config file.
        with open('config.yml', 'r') as cfg_file:
            self.config = yaml.load(cfg_file)

    def add_banner_grab(self, banner):
        self.banner = banner

    @staticmethod
    def log_open_port(host, port, status):
        """ Logs any host with an open port to a file. """
        time_now = datetime.now()
        event = " host={0}, port={1}, status='{2}'\n".format(colored(host, 'red'), colored(port, 'red'),
                                                             colored(status, 'green'))
        print "[*] Open port found:{0}".format(event)
        with open("open_ports.log", 'a') as log_file:
            log_file.write(str(time_now))
            log_file.write(event)

    @staticmethod
    def log_results(host, port, user, password, protocol):
        """ Logs credentials that are successfully recovered. """
        time_now = str(datetime.now())
        print "[*] Recording successful attempt:"
        event = " host={0}, port={1}, user='{2}', password='{3}', protocol='{4}'\n".format(host, port, user, password,
                                                                                           protocol)
        print "[*] Password recovered:{0}".format(event)
        with open("recovered_passwords.log", 'a') as log_file:
            log_file.write(time_now)
            log_file.write(event)

    def log_error(self, service, error):
        """ Logs any Exception or error that is thrown by the program. """
        time_now = datetime.now()
        log_error_message = "{0} service={1}, error={2}\n".format(str(time_now), service, str(error))
        with open('error.log', 'a') as f:
            f.write(log_error_message)
            if self.verbose:
                print "[*] Error logged: {0}: {1}".format(service, error)

    def log_service_error(self, host, port, service, error):
        """ Logs any Exception or error related to testing credentials through a service. """
        time_now = datetime.now()
        log_error_message = str(time_now) + " host={0}, port={1}, service={2}, error={3}\n".format(host, port,
                                                                                                   service,
                                                                                                   str(error))
        with open('error.log', 'a') as f:
            f.write(log_error_message)
            if self.verbose:
                print "[*] Error logged: {1}".format(log_error_message)

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
        """Scans for a live host and for any open common admin ports defined in the configuration file.
        If an open port is found, it instantiates a class for that host and records all the open ports.

        Tests all live host for open 'admin' ports

        Changed to let NMAP handling the threading. Had implemented threading, but threading NMAP,
        which is threaded seems to add complications. New implementation is very fast and almost no issues.

        Ports list as argument needed to have the whitespace stripped between each port, otherwise the NMAP command
        is not constructed properly.
        """
        # TODO: Add up percentage like in live hosts above.
        service = "admin_port_scanner"
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
            self.log_error(service, error)
        except KeyboardInterrupt:
            exit(0)


class VulnerableHost(HoneyHornet):
    """ Defines a class for each live host with an open admin port and saves the open ports to a list. These objects
     are then used when the CheckCredentials() class is instantiated and services checked.
     """
    def __init__(self, ipaddr):
        HoneyHornet.__init__(self)
        self.ports = []
        self.credentials = []
        self.banner = []
        self.ip = ipaddr

    def add_vulnerable_port(self, port):
        """ Function appends open admin port to list. """
        self.ports.append(port)

    def put_credentials(self, new_credentials):
        """ Records credentials of a successful login attempt to an open admin port. """
        self.credentials.append(new_credentials)

    def put_banner(self, port, banner_txt, status, reason, headers):
        """ Adds port, banner to banner list of a port that is defined in the http_ports list or is not handled
         by another service check.
         """
        self.banner.append(':{0} {1} {2} {3}\n{4}\n'.format(port, status, reason, banner_txt, headers))


class CheckCredentials(VulnerableHost):
    """ CheckCredentials() defines all the methods to check each service for all the credentials defined. Right now the
    supported services are:

        1. Telnet
        2. FTP - anonymous login
        3. FTP - with credentials
        4. SSH (with legacy ssh-dss support)
        5. Web Authentication over HTTP (using xml files)
        6. Banner grabs for open ports

    It also builds the credential list from the users and passwords defined in the configuration file. It builds a
    nested list of every combination of username and password. For each 'credential' in the list index[0] is the
    username and index[1] is the password. Example: [('user', 'pass'), ('admin', '12345')]

    The final method is run_credential_test() sets up and runs threads for each target and port/service. Max number of
    threads that can be run in parallel is defined in the HoneyHornet class (default=20) but depending on the hardware
    that might be need to be adjusted.
    """
    def __init__(self):
        HoneyHornet.__init__(self)
        # TODO: add/modify http_ports list
        self.http_ports = [8000, 8080, 8081, 8090, 9191, 9443]
        self.telnet_ports = [23, 2332]

    def build_credentials(self):
        """ Function takes the usernames and passwords from the configuration file and constructs the credential list.
        """
        service = "credential_builder"
        try:
            users = self.config['users']
            passwords = self.config['passwords']
            credentials = list(itertools.product(users, passwords))
            return credentials
        except Exception as error:
            self.log_error(service, error)
            return False
        except KeyboardInterrupt:
            exit(0)

    def check_telnet(self, vulnerable_host, port, credentials):
        """ Tries to connect via Telnet with common credentials. Then it prints the results of the connection attempt.
        Due to the way TELNETLIB works and the different implementations of telnet. This is fairly inefficient way to
        test credentials. Really needs to be customized based on the telnet implementation. Web-based credential testing
        is much better and more standardized.

        UPDATE: Found that using a time.sleep() pause is a much more effective way of inputting credentials when
        testing. For the ALEOS from Sierra Wireless an "OK" response is received almost immediately when the correct
        credentials are supplied. When the wrong credentials are supplied, the response is much more delayed.
        A 3 second timeout has been effective in differentiating between a successful and failed login attempt.
        """
        service = "TELNET"
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            for credential in credentials:
                user = credential[0]
                password = credential[1]
                if self.verbose:
                    print "[*] Testing Telnet connection on {0}...".format(host)
                    print "[*] username: {0} password: {1} port: {2}".format(user, password, port)
                t = telnetlib.Telnet(host, port, 15)
                time.sleep(self.TIMER_DELAY)
                t.write(user + "\r\n")
                time.sleep(self.TIMER_DELAY)
                t.write(password + "\r\n")
                time.sleep(self.TIMER_DELAY)
                server_response = t.read_very_eager()
                if self.verbose:
                    print server_response
                if "OK" in server_response:
                    self.log_results(host, port, user, password, service)
                    t.close()
                    return True
                elif "incorrect" in server_response:
                    error = "Password incorrect."
                    self.log_service_error(host, port, service, error)
                    t.close()
                    return False
                else:
                    t.close()
                    return False
        except Exception as error:
            self.log_service_error(host, port, service, error)
            return False
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    def check_ftp_anon(self, vulnerable_host):
        """ Function checks the FTP service for anonymous log-ins and does an FTP banner grab """
        port = "21"
        user = "Anonymous"
        password = "none"
        protocol = "FTP"
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            if self.verbose:
                print "[*] Testing FTP connection on {0}...".format(host)
            ftp_conn = FTP(host)
            ftp_conn.login()
            ftp_conn.quit()
            ftp_welcome = ftp_conn.getwelcome()
            self.log_results(host, port, user, password, protocol)
            if self.verbose:
                print "[+] FTP server responded with {0}".format(ftp_welcome)
            return True
        except Exception as error:
            self.log_service_error(host, port, protocol, error)
            return False
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    def check_ftp(self, vulnerable_host, credentials):
        """ Checks the host for FTP connection using username and password combinations """
        port = "21"
        service = "FTP"
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            for credential in credentials:
                user = credential[0]
                password = credential[1]
                if self.verbose:
                    print "[*] Testing FTP connection on {0}...".format(host)
                try:
                    ftp_conn = FTP()
                    if ftp_conn.connect(host, 21, 1):
                        ftp_welcome = ftp_conn.getwelcome()
                        if self.verbose:
                            print "[*] FTP server returned {0}".format(ftp_welcome)
                        ftp_conn.login(user, password)
                        ftp_conn.close()
                        self.log_results(host, port, user, password, service)
                    break
                except Exception as error:
                    self.log_service_error(host, port, service, error)
                except KeyboardInterrupt:
                    exit(0)
        except Exception as error:
            self.log_error(service, error)
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    def check_ssh(self, vulnerable_host, credentials):
        """ Function tests the SSH service with all of the users and passwords given """
        port = "22"
        service = "SSH"
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            if self.verbose:
                print "[*] Testing SSH service on {0}...".format(host)
            for credential in credentials:
                try:
                    user = str(credential[0])
                    password = str(credential[1])
                    # This works for up-to-date SSH servers:
                    # ssh_conn = pxssh.pxssh()
                    # Old SSH servers running "ssh-dss" needs this option instead:
                    ssh_conn = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "HostKeyAlgorithms": "+ssh-dss"})
                    ssh_conn.login(host, user, password)
                    self.log_results(host, port, user, password, service)
                    ssh_conn.logout()
                    ssh_conn.close()
                except pxssh.EOF as EOF_error:
                    self.log_service_error(host, port, service, EOF_error)
                except pxssh.ExceptionPxssh as error:
                    self.log_service_error(host, port, service, error)
                except KeyboardInterrupt:
                    exit(0)
        except threading.ThreadError as thread_error:
            self.log_error(service, thread_error)
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    def banner_grab(self, vulnerable_host):
        """ simple banner grab with HTTPLIB """
        service = "HTTP-BANNER-GRAB"
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            if self.verbose:
                print "[*] Grabbing banner from {0}".format(host)
            ports_to_check = set(self.http_ports) & set(vulnerable_host.ports)
            for http_port in ports_to_check:
                conn = httplib.HTTPConnection(host, http_port)
                conn.request("GET", "/")
                http_r1 = conn.getresponse()
                banner_txt = http_r1.read(1000)
                headers = http_r1.getheaders()
                if self.verbose:
                    print http_r1.status, http_r1.reason
                # puts banner into the class instance of the host
                vulnerable_host.put_banner(http_port, banner_txt, http_r1.status, http_r1.reason, headers)
                with open('banner_grabs.log') as banner_log:
                    banner_to_log = "host={0}, http_port={1},\nheaders={2},\nbanner={3}\n".format(host, http_port,
                                                                                                  headers, banner_txt)
                    banner_log.write(banner_to_log)
        except Exception as error:
            if host is None:
                host = ""
            if http_port is None:
                http_port = ""
            self.log_service_error(host, http_port, service, error)
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    def http_post_xml(self, vulnerable_host):
        """ Tests for default credentials against an Web-based Authentication
        Reads and POSTs data via XML files.
        This only handles one specific type of Web-based Authentication at this time.
        """
        self.CONNECTION_LOCK.acquire()
        print "[*] Attempting to validate credentials via HTTP-POST..."
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
                    password_to_use = m[0]
                    if self.verbose:
                        print password_to_use
                    return password_to_use
                else:
                    print "[!] Error: unable to extract password from xml file."

        def read_xml(xml_file):
            """ Reads the XML file to put in body of request """
            with open(xml_file, 'r') as xml_to_load:
                xml_payload = xml_to_load.read()
                return xml_payload

        # Tries to connect to host via HTTP-POST w/ the XML authentication in the body of the request.
        # Uses Regular Expressions to extract errors for debugging/tuning the program.
        try:
            for http_port in ports_to_check:
                conn = httplib.HTTPConnection(host, http_port, timeout=25)
                xml = read_xml(xml_connect)
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
                self.log_service_error(host, http_port, method, error)
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    def run_credential_test(self, hosts_to_check):
        """ Function tests hosts for default credentials on open 'admin' ports
        Utilizes threading to greatly speed up the scanning
        """
        service = "building_threads"
        credentials_to_check = self.build_credentials()
        threads = []
        print "[*] Testing vulnerable host ip addresses..."
        try:
            for vulnerable_host in hosts_to_check:
                if self.verbose:
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
                        t = threading.Thread(target=self.check_telnet, args=(vulnerable_host, port,
                                                                             credentials_to_check))
                        threads.append(t)
                if set(self.http_ports) & set(vulnerable_host.ports):
                    t0 = threading.Thread(target=self.http_post_xml, args=(vulnerable_host, ))
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
        except threading.ThreadError as error:
            self.log_error(service, error)
        except Exception:
            raise


def main():
    """ Main program """
    start_time = datetime.now()
    # TODO: add resume option (read from file)

    hh = HoneyHornet()

    print "[*] Using default YAML config file..."
    target_hosts = hh.config['targets']
    ports_to_scan = hh.config['ports']
    scan_type = str(hh.config['scanType']).strip('[]')
    banner = hh.config['bannerGrab']
    if banner is True:
        hh.add_banner_grab(banner)

    service = "run_scan_type"
    try:
        if scan_type == '1':
            print "[*] Running in port scanner mode..."
            hh.check_admin_ports(target_hosts, ports_to_scan)
        elif scan_type == '2':
            print "[*] Running in credential check mode..."
            hh.check_admin_ports(target_hosts, ports_to_scan)
            hosts_to_check = hh.vulnerable_hosts
            CheckCredentials().run_credential_test(hosts_to_check)
        else:
            print "[!] Please define a scan type in config file!"
            exit(0)
    except KeyboardInterrupt:
        exit(0)
    except Exception as error:
        hh.log_error(service, error)
    finally:
        print datetime.now() - start_time  # Calculates run time for the program.


if __name__ == "__main__":
    main()
