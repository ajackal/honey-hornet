#! /usr/bin/env python

from honeyhornet import HoneyHornet, VulnerableHost
import argparse
import logging
from datetime import date, datetime
import telnetlib
from ftplib import FTP
import threading
import httplib
import re
from pexpect import pxssh
import time
import itertools


class CredentialChecker(HoneyHornet):
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

    def log_results(self, host, port, user, password, protocol):
        """ Logs credentials that are successfully recovered. """
        logfile_name = str(date.today()) + "_recovered_passwords.log"
        print "[*] Recording successful attempt:"
        event = " host={0}\tport={1}\tuser='{2}'\tpassword='{3}'\tprotocol='{4}'\n".format(host, port, user, password,
                                                                                           protocol)
        print "[*] Password recovered:{0}".format(event)
        self.write_log_file(logfile_name, event)

    def build_credentials(self):
        """ Function takes the usernames and passwords from the configuration file and constructs every possible
        combination into a single credential list.

        Example from 'config.yml':
        [...snip...]
            users:
                - bob
                - sally

            passwords:
                - 12345
                - secret
        [...snip...]

        credentials = build_credentials()
        credentials = [('bob', '12345'), ('bob', 'secret'), ('sally', '12345'), ('sally', 'secret')]

        Then each username can be accessed with credentials[0] and each password with credentials[1]. Simplifies the
        iteration through every credential combination.
        """
        try:
            users = self.config['users']
            passwords = self.config['passwords']
            credentials = list(itertools.product(users, passwords))
            logging.info('Credentials built successfully.')
            return credentials
        except Exception as error:
            logging.exception(error)
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
            logging.info('{0} set for {1} service'.format(host, service))
            for credential in credentials:
                user = str(credential[0])
                password = str(credential[1])
                logging.info('Checking {0}:{1} on {2} for {3} service.'.format(user, password, host, service))
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
                    self.vulnerable_hosts.put_credentials(service, port, user, password)
                    t.close()
                elif "incorrect" in server_response:
                    error = "Password incorrect."
                    logging.error("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                    t.close()
                else:
                    t.close()
        except Exception as error:
            logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    def check_ftp_anon(self, vulnerable_host):
        """ Function checks the FTP service for anonymous log-ins and does an FTP banner grab """
        ftp_anon = {'port': '21',
                    'user': 'Anonymous',
                    'password': 'none',
                    'service': 'FTP'
                    }
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            logging.info('{0} set for {1} service'.format(host, ftp_anon['service']))
            if self.verbose:
                print "[*] Testing FTP connection on {0}...".format(host)
            ftp_conn = FTP(host)
            ftp_conn.login()
            ftp_conn.quit()
            ftp_welcome = ftp_conn.getwelcome()
            self.log_results("{0}\t{1}\t{2}\t{3}\t{4}".format(host, ftp_anon['port'], ftp_anon['user'],
                                                              ftp_anon['password'], ftp_anon['service']))
            self.vulnerable_hosts.put_credentials(ftp_anon['service'], ftp_anon['port'], ftp_anon['user'],
                                                  ftp_anon['password'])
            if self.verbose:
                print "[+] FTP server responded with {0}".format(ftp_welcome)
            return True
        except Exception as error:
            logging.exception("{0}\t{1}\t{2}\t{3}".format(host, ftp_anon['port'], ftp_anon['service'], error))
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
            logging.info('{0} set for {1} service'.format(host, service))
            for credential in credentials:
                user = credential[0]
                password = str(credential[1])
                logging.info('Checking {0}:{1} on {2} for {3} service.'.format(user, password, host, service))
                if self.verbose:
                    print "[*] Testing FTP connection on {0}...".format(host)
                try:
                    ftp_conn = FTP()
                    if ftp_conn.connect(host, 21, 1):
                        ftp_welcome = ftp_conn.getwelcome()
                        logging.info("{0} FTP server returned {1}".format(host, ftp_welcome))
                        if self.verbose:
                            print "[*] FTP server returned {0}".format(ftp_welcome)
                        ftp_conn.login(user, password)
                        ftp_conn.close()
                        self.log_results(host, port, user, password, service)
                        self.vulnerable_hosts.put_credentials(service, port, user, password)
                    break
                except Exception as error:
                    logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                except KeyboardInterrupt:
                    exit(0)
        except Exception as error:
            logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    def check_ssh(self, vulnerable_host, credentials):
        """ Function tests the SSH service with all of the users and passwords given.
        
        1. pxssh.pxssh() works for up-to-date implementations of OpenSSLs SSH.
        2. If testing against LEGACY SSH implementations you need to add several options to handle it properly:
                pxssh.pxssh(options={"StrictHostKeyChecking": "no", "HostKeyAlgorithms": "+ssh-dss"})
                This will disable strict host checking and enable support for SSH-DSS working with most LEGACY SSH implementations.
         """
        port = "22"
        service = "SSH"
        try:
            self.CONNECTION_LOCK.acquire()
            host = vulnerable_host.ip
            logging.info('{0} set for {1} service'.format(host, service))
            if self.verbose:
                print "[*] Testing SSH service on {0}...".format(host)
            for credential in credentials:
                try:
                    user = str(credential[0])
                    password = str(credential[1])
                    logging.info('Checking {0}:{1} on {2} for {3} service.'.format(user, password, host, service))
                    # This works for up-to-date SSH servers:
                    # ssh_conn = pxssh.pxssh()
                    # Old SSH servers running "ssh-dss" needs this option instead:
                    ssh_conn = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "HostKeyAlgorithms": "+ssh-dss"})
                    ssh_conn.login(host, user, password)
                    self.log_results(host, port, user, password, service)
                    self.vulnerable_hosts.put_credentials(service, port, user, password)
                    ssh_conn.logout()
                    ssh_conn.close()
                except pxssh.EOF as EOF_error:
                    logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, EOF_error))
                except pxssh.ExceptionPxssh as error:
                    logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                except KeyboardInterrupt:
                    exit(0)
        except threading.ThreadError as thread_error:
            logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, thread_error))
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    # TODO: continute refining keyword arguments
    def banner_grab(self, vulnerable_host, **kwargs):
        """ simple banner grab with HTTPLIB """
        service = "HTTP-BANNER-GRAB"
        # self.CONNECTION_LOCK.acquire()
        try:
            host = vulnerable_host.ip
            ports_to_check = set(self.http_ports) & set(vulnerable_host.ports)
        except:
            host = str(vulnerable_host)
            if 'ports' in kwargs:
                ports_to_check = set(**kwargs[ports].split(','))
        # if self.verbose:
        logging.info('{0} set for {1} service'.format(host, service))
        print "[*] Grabbing banner from {0}".format(host)
        try:
            for port in ports_to_check:
                if 'https' in kwargs is True:
                    conn = httplib.HTTPSConnection(host, port)
                else:
                    conn = httplib.HTTPConnection(host, port)
                conn.request("GET", "/")
                http_r1 = conn.getresponse()
                banner_txt = http_r1.read(1024)
                headers = http_r1.getheaders()
                if self.verbose:
                    print http_r1.status, http_r1.reason
                # puts banner into the class instance of the host
                vulnerable_host.put_banner(port, banner_txt, http_r1.status, http_r1.reason, headers)
                banner_grab_filename = str(date.today()) + " banner_grabs.log"
                with open(banner_grab_filename, 'a') as banner_log:
                    banner_to_log = "host={0}, http_port={1},\nheaders={2},\nbanner={3}\n".format(host, port,
                                                                                                  headers, banner_txt)
                    banner_log.write(banner_to_log)
        except httplib.HTTPException:
            try:
                self.banner_grab(host, https=True)
            except Exception as error:
                logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
        except Exception as error:
            logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
        except KeyboardInterrupt:
            exit(0)
        # finally:
        #     self.CONNECTION_LOCK.release()

    def http_post_xml(self, vulnerable_host):
        """ Tests for default credentials against an Web-based Authentication
        Reads and POSTs data via XML files.
        This only handles one specific type of Web-based Authentication at this time.
        """
        self.CONNECTION_LOCK.acquire()
        service = "WEB-AUTH-XML"
        if self.verbose:
            print "[*] Attempting to validate credentials via HTTP-POST..."
        host = vulnerable_host.ip
        logging.info('{0} set for {1} service'.format(host, service))
        ports_to_check = set(self.http_ports) & set(vulnerable_host.ports)
        logging.info("Checking {0} ports on {1} for {2}".format(ports_to_check, host, service))
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
                   "Content-Type": "text/xml",
                   "Accept": "application/xml, text/xml, */*; q=0.01",
                   "Accept-Language": "en-US,en;q=0.5",
                   "X-Requested-With": "XMLHttpRequest",
                   "Connection": "close"}

        xml_connect_path = "xml/Connect.xml"

        method = "HTTP-POST"

        def get_pass_from_xml():
            """ Extracts the password from the xml file. Uses this when recording the results """
            with open(xml_connect_path) as f:
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
            with open(xml_connect_path) as f:
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
            for port in ports_to_check:
                conn = httplib.HTTPConnection(host, port, timeout=25)
                xml_body = read_xml(xml_connect_path)
                conn.request("POST", "/xml/Connect.xml", xml_body, headers)
                response = conn.getresponse()
                if self.verbose:
                    print response.status, response.reason
                data = response.read()
                if "message='OK'" in data:
                    user = get_user_from_xml()
                    password = get_pass_from_xml()
                    self.log_results(host, port, user, password, service)
                    self.vulnerable_hosts.put_credentials(service, port, user, password)
                else:
                    error_msg = re.findall(r"message='(?P<error>.*)'", str(data))
                    if error_msg:
                        error = error_msg[0]
                        print "[*] Server returned: {0}".format(error)
                        logging.error("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                    else:
                        print "[*] Server returned an error."
                conn.close()
        except Exception as error:
            error_msg = re.findall(r"message='(?P<error>.*)'", str(error))
            if error_msg:
                error = error_msg[0]
                logging.exception("{0}\t{1}\t{2}".format(host, service, error))
        except KeyboardInterrupt:
            exit(0)
        finally:
            self.CONNECTION_LOCK.release()

    def run_credential_test(self, hosts_to_check):
        """ Function tests hosts for default credentials on open 'admin' ports
        Utilizes threading to greatly speed up the scanning
        """
        service = "building_threads"
        logging.info("Building threads.")
        logging.info("Verbosity set to {0}".format(self.verbose))
        logging.info("Banner Grab variable set to {0}".format(self.banner))
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
            logging.info("Starting {0} threads.".format(len(threads)))
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(120)
        except KeyboardInterrupt:
            exit(0)
        except threading.ThreadError as error:
            logging.exception("{0}\t{1}".format(service, error))
        except Exception:
            raise


def main():
    cc = CredentialChecker()
    start_time = datetime.now()
    # TODO: add resume option (read from file)
    parser = argparse.ArgumentParser(description="Check a host for login credentials.")
    parser.add_argument(['-t', '--target'], dest='target', type='string', required=True,
                        help='IP address to test')
    parser.add_argument(['-s', '--service'], dest='service', type='string', required=True,
                        help='The protocol you want to check: FTP, SSH, TELNET, HTTP-XML')
    parser.add_argument(['-c', '--credentials'], dest='credentials', type='string', required=True,
                        help='Credentials to test. Format= username:password ')
    parser.add_argument(['-h', '--http-port'], dest='http_port', type='int', help='HTTP port to test.')
    args = parser.parse_args()

    credentials = args.credenitals.split(':')

    log_name = str(date.today()) + " DEBUG.log"
    logging.basicConfig(filename=log_name, format='%(asctime)s %(levelname)s: %(message)s',
                        level=logging.DEBUG)

    if args.service is 'FTP':
        cc.check_ftp_anon(args.target)
        cc.check_ftp(args.target, credentials)
    elif args.service is 'SSH':
        cc.check_ssh(args.target, credentials)
    elif args.service is 'TELNET':
        cc.check_telnet(args.target, 23, credentials)
    elif args.service is 'HTTP-XML':
        cc.http_post_xml(args.target)
    else:
        print "[!] Unknown service. Please use: FTP, SSH, TELNET, HTTP-XML"

    print datetime.now() - start_time  # Calculates run time for the program.


if __name__ == '__main__':
    main()
