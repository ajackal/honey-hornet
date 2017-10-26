from honeyhornet import HoneyHornet, VulnerableHost
import telnetlib
from ftplib import FTP
import threading
import httplib
import re
from termcolor import colored
from pexpect import pxssh
import time
import itertools


class CredentialChecker(VulnerableHost):
    """ CredentialChecker() defines all the methods to check each service for all the credentials defined. Right now the
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
                password = str(credential[1])
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
        if self.verbose:
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

        def get_user_from_xml():
            """ Extracts the username from the xml file. Uses this when recording the results """
            with open(xml_connect) as f:
                x = f.read()
                m = re.findall(r"<login>(?P<username>\w*)</login>", x)
                if m:
                    username = m[0]
                    if self.verbose:
                        print username
                    return username
                else:
                    print "[!] Error: unable to extract username from xml file."

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
                conn.request("POST", "/xml/Connect.xml", xml, headers)
                response = conn.getresponse()
                if self.verbose:
                    print response.status, response.reason
                data = response.read()
                if "message='OK'" in data:
                    user = get_user_from_xml()
                    password = get_pass_from_xml()
                    protocol = "WEB-AUTH"
                    self.log_results(host, http_port, user, password, protocol)
                else:
                    error_msg = re.findall(r"message='(?P<error>.*)'", str(data))
                    if error_msg:
                        error = error_msg[0]
                        print "[*] Server returned: {0}".format(error)
                    else:
                        print "[*] Server returned an error."
                conn.close()
        except Exception as error:
            error_msg = re.findall(r"message='(?P<error>.*)'", str(error))
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

