import os
import argparse
from honeyhornet import logger
from threading import BoundedSemaphore
import logging
from datetime import date, datetime
from termcolor import colored
import telnetlib
from ftplib import FTP
import threading
import requests
import re
from pexpect import pxssh
import time
import itertools


class CredentialChecker(logger.HoneyHornetLogger):
    """ CredentialChecker() defines all the methods to check each service for all the credentials defined.

    Note:
        Right now the supported services are:
            - Telnet
            - FTP - anonymous login
            - FTP - with credentials
            - SSH (with legacy ssh-dss support)
            - Web Authentication over HTTP (using xml files)
            - Banner grabs for open ports

    It also builds the credential list from the users and passwords defined in the configuration file. It builds a
    nested list of every combination of username and password. For each 'credential' in the list index[0] is the
    username and index[1] is the password. Example: [('user', 'pass'), ('admin', '12345')]

    The final method is run_credential_test() sets up and runs threads for each target and port/service. Max number of
    threads that can be run in parallel is defined in the HoneyHornet class (default=20) but depending on the hardware
    that might be need to be adjusted.

    Attributes:
        http_ports (list): list of integer ports that you want to use when scanning http protocol.
        telnet_ports (list): list of integers to test using the telnet protocol
        config (str): a string that will hold the configuration to run.
        verbose (bool): True enables verbose output, default False.
        banner (bool): True enables banner grabbing, default False.
        MAX_CONNECTIONS (int): constant defining max number of threads
        CONNECTION_LOCK (:obj:``BoundedSemaphore``): object defining the type of threading and max connnections.
        TIMER_DELAY (int): number of seconds to delay when logging in
        default_filepath (str): default file path used when saving results to disk
        log_name (str): base file name used for the DEBUG log.
    """
    def __init__(self, config=None):
        logger.HoneyHornetLogger.__init__(self)
        # TODO: add/modify http_ports list
        self.http_ports = [8000, 8080, 8081, 8090, 9191, 9443]
        self.telnet_ports = [23, 2332]
        self.config = config
        self.verbose = False
        self.banner = False
        MAX_CONNECTIONS = 20  # max threads that can be created
        self.CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTIONS)
        self.TIMER_DELAY = 3  # timer delay used for Telnet testing
        self.default_filepath = os.path.split(os.path.dirname(__file__))[0]
        log_name = str(date.today()) + "_DEBUG.log"
        log_name = os.path.join(self.default_filepath, "logs", log_name)
        logging.basicConfig(filename=log_name, format='%(asctime)s %(levelname)s: %(message)s',
                            level=logging.DEBUG)
        
    def log_results(self, host, port, user, password, protocol):
        """ Logs credentials that are successfully recovered to a file on disk.

         Args:
             host (str): IP Address of the host with recovered credentials.
             port (str): port that the service was running on.
             user (str): username that was recovered.
             password (str): password that was recovered.
             protocol (str): the service that was running and used to recover the credentials.

         Returns:
             bool: True for success, False otherwise.
        """
        try:
            logfile_name = str(date.today()) + "_recovered_passwords.log"
            log_name = os.path.join(self.default_filepath, "logs", logfile_name)
            event = " host={0}\tuser={1}\tpassword={2}   \tport={3}  \tprotocol={4}".format(colored(host, "green"),
                                                                                            colored(user, "red"),
                                                                                            colored(password, "red"),
                                                                                            port,
                                                                                            protocol)
            print("[*] Password recovered:{0}".format(event))
            self.write_log_file(log_name, "\n")
            self.write_log_file(log_name, event)
            return True
        except IOError:
            return False

    def build_credentials(self):
        """ Function takes the usernames and passwords from the configuration file and constructs every possible
        combination into a single credential list.

        Example:
             from 'config.yml':
        [...snip...]
            users:
                - bob
                - sally

            passwords:
                - 12345
                - secret
        [...snip...]

        >>> credentials = build_credentials()
        >>> credentials
        >>> [('bob', '12345'), ('bob', 'secret'), ('sally', '12345'), ('sally', 'secret')]

        Then each username can be accessed with credentials[0] and each password with credentials[1]. Simplifies the
        iteration through every credential combination.

        Returns:
            credentials (list): a list of string tuples with every combination of username and password.

        """
        users = self.config['users']
        passwords = self.config['passwords']
        try:
            credentials = list(itertools.product(users, passwords))
            logging.info('Credentials built successfully.')
            return credentials
        except Exception as error:
            logging.exception(error)
        except KeyboardInterrupt:
            exit(0)

    def check_telnet(self, vulnerable_host, port, credentials):
        """ Tries to connect via Telnet with common credentials. Then it prints the results of the connection attempt.

        Note:
            Due to the way TELNETLIB works and the different implementations of telnet. This is fairly inefficient way
            to test credentials. Really needs to be customized based on the telnet implementation. Web-based credential
            testing is much better and more standardized.

        UPDATE: Found that using a time.sleep() pause is a much more effective way of inputting credentials when
        testing. For the ALEOS from Sierra Wireless an "OK" response is received almost immediately when the correct
        credentials are supplied. When the wrong credentials are supplied, the response is much more delayed.
        A 3 second timeout has been effective in differentiating between a successful and failed login attempt.

        Args:
            vulnerable_host (object): the vulnerable host object that will be tested.
            port (int): the port to use to test the Telnet connection.
            credentials (list): a list holding string tuples of the credentials to test.

        Returns:
            bool: True for success, False otherwise.
        """
        self.CONNECTION_LOCK.acquire()
        service = "TELNET"
        host = vulnerable_host.ip
        logging.info('{0} set for {1} service'.format(host, service))
        for credential in credentials:
            user = str(credential[0])
            password = str(credential[1])
            logging.info('Checking {0}:{1} on {2} for {3} service.'.format(user, password, host, service))
            if self.verbose:
                print("[*] Testing Telnet connection on {0}...".format(host))
                print("[*] username: {0} password: {1} port: {2}".format(user, password, port))
            try:
                t = telnetlib.Telnet(host, port, 15)
                t.open(host)
                # time.sleep(self.TIMER_DELAY)
                t.read_until(b"login: ")
                t.write(user.encode('ascii') + b"\r\n")
                # time.sleep(self.TIMER_DELAY)
                t.read_until(b"assword: ")
                t.write(password.encode('ascii') + b"\r\n")
                # time.sleep(self.TIMER_DELAY)
                server_response = t.read_until(b'OK').decode('ascii')
                t.close()
                # server_response = t.read_eager()
                # server_response = t.read_all().decode('ascii')
                logging.info("Telnet server {0}:{1} returned:\n{2}".format(host, port, server_response))
                if self.verbose:
                    print(server_response)
                if "OK" in server_response:
                    self.log_results(host, port, user, password, service)
                    vulnerable_host.put_credentials(service, port, user, password)
                    t.close()
                    return True
                elif "incorrect" in server_response:
                    error = "Password incorrect."
                    logging.error("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                    t.close()
                    return False
                else:
                    t.close()
                    return False
            except Exception as error:
                logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                return False
            except KeyboardInterrupt:
                exit(0)
        self.CONNECTION_LOCK.release()

    def check_ftp_anon(self, vulnerable_host):
        """Function checks the FTP service for anonymous log-ins and does an FTP banner grab

        Args:
            vulnerable_host (object): object of the vulnerable host that will be tested.

        Returns:
            bool: True for success, False otherwise.
        """
        self.CONNECTION_LOCK.acquire()
        ftp_anon = {
                    'port': '21',
                    'user': 'Anonymous',
                    'password': 'none',
                    'service': 'FTP'
                    }
        host = vulnerable_host.ip
        logging.info('{0} set for {1} service'.format(host, ftp_anon['service']))
        if self.verbose:
            print("[*] Testing FTP connection on {0}...".format(host))
        try:
            ftp_conn = FTP(host)
            ftp_conn.login()
            ftp_conn.quit()
            ftp_welcome = ftp_conn.getwelcome()
            self.log_results("{0}\t{1}\t{2}\t{3}\t{4}".format(host, ftp_anon['port'], ftp_anon['user'],
                                                              ftp_anon['password'], ftp_anon['service']))
            vulnerable_host.put_credentials(ftp_anon['service'], ftp_anon['port'], ftp_anon['user'],
                                            ftp_anon['password'])
            if self.verbose:
                print("[+] FTP server responded with {0}".format(ftp_welcome))
            return True
        except Exception as error:
            logging.exception("{0}\t{1}\t{2}\t{3}".format(host, ftp_anon['port'], ftp_anon['service'], error))
            return False
        except KeyboardInterrupt:
            exit(0)
        self.CONNECTION_LOCK.release()

    def check_ftp(self, vulnerable_host, credentials):
        """ Checks the host for FTP connection using username and password combinations

         Args:
            vulnerable_host (object): object of the vulnerable host that will be tested.
            credentials (list): a list holding string tuples of the credentials to test.

        Returns:
            bool: True for success, False otherwise.
        """
        self.CONNECTION_LOCK.acquire()
        port = "21"
        service = "FTP"
        host = vulnerable_host.ip
        logging.info('{0} set for {1} service'.format(host, service))
        for credential in credentials:
            user = str(credential[0])
            password = str(credential[1])
            logging.info('Checking {0}:{1} on {2} for {3} service.'.format(user, password, host, service))
            if self.verbose:
                print("[*] Testing FTP connection on {0}...".format(host))
            try:
                ftp_conn = FTP()
                if ftp_conn.connect(host, 21, 1):
                    ftp_welcome = ftp_conn.getwelcome()
                    logging.info("{0} FTP server returned {1}".format(host, ftp_welcome))
                    if self.verbose:
                        print("[*] FTP server returned {0}".format(ftp_welcome))
                    ftp_conn.login(user, password)
                    ftp_conn.close()
                    self.log_results(host, port, user, password, service)
                    vulnerable_host.put_credentials(service, port, user, password)
                    return True
                break
            except Exception as error:
                logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                return False
            except KeyboardInterrupt:
                exit(0)
        self.CONNECTION_LOCK.release()

    def check_ssh(self, vulnerable_host, credentials):
        """ Function tests the SSH service with all of the users and passwords given.
        
        1. pxssh.pxssh() works for up-to-date implementations of OpenSSLs SSH.
        2. If testing against LEGACY SSH implementations you need to add several options to handle it properly:
                pxssh.pxssh(options={"StrictHostKeyChecking": "no", "HostKeyAlgorithms": "+ssh-dss"})
                This will disable strict host checking and enable support for SSH-DSS working with most
                LEGACY SSH implementations.

        Args:
            vulnerable_host (object): object of the vulnerable host that will be tested.
            credentials (list): a list holding string tuples of the credentials to test.

        Returns:
            bool: True for success, False otherwise.
         """
        self.CONNECTION_LOCK.acquire()
        port = "22"
        service = "SSH"
        host = vulnerable_host.ip
        logging.info('{0} set for {1} service'.format(host, service))
        if self.verbose:
            print("[*] Testing SSH service on {0}...".format(host))
        for credential in credentials:
            user = str(credential[0])
            password = str(credential[1])
            logging.info('Checking {0}:{1} on {2} for {3} service.'.format(user, password, host, service))
            try:
                # This works for up-to-date SSH servers:
                # ssh_conn = pxssh.pxssh()
                # Old SSH servers running "ssh-dss" needs this option instead:
                ssh_conn = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "HostKeyAlgorithms": "+ssh-dss"})
                ssh_conn.login(server=host, username=user, password=password)
                self.log_results(host, port, user, password, service)
                vulnerable_host.put_credentials(service, port, user, password)
                ssh_conn.logout()
                ssh_conn.close()
                return True
            except pxssh.EOF as EOF_error:
                logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, EOF_error))
                return False
            except pxssh.ExceptionPxssh as error:
                logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                return False
            except KeyboardInterrupt:
                exit(0)
        self.CONNECTION_LOCK.release()

    def banner_grab(self, vulnerable_host, ports=None, https=False):
        """Simple banner grab with Requests module.

        Args:
            vulnerable_host (object): object of the vulnerable host that will be tested.
            ports (list): list of ints of ports to grab banners from.
            https (bool): Default False, if True uses an HTTPS connection.

        Returns:
            bool: True for success, False otherwise.
        """
        self.CONNECTION_LOCK.acquire()
        service = "HTTP-BANNER-GRAB"
        try:
            host = vulnerable_host.ip
            ports_to_check = set(self.http_ports) & set(vulnerable_host.ports)
        except vulnerable_host.DoesNotExist:
            host = str(vulnerable_host)
            ports_to_check = set(ports.split(',').strip())
        if self.verbose:
            print("[*] Grabbing banner from {0}".format(host))
        logging.info('{0} set for {1} service'.format(host, service))
        try:
            for port in ports_to_check:
                if https is True:
                    connection_address = "https://{0}:{1}".format(host, port)
                else:
                    connection_address = "http://{0}:{1}".format(host, port)
                response = requests.get(connection_address)
                banner_txt = response.text
                headers = response.headers
                if self.verbose:
                    print(response.status_code, response.reason)
                # puts banner into the class instance of the host
                vulnerable_host.put_banner(port, banner_txt, response.status_code, response.reason, headers)
                banner_grab_filename = str(date.today()) + "_banner_grabs.log"
                banner_grab_filename = os.path.join(self.default_filepath, "logs", banner_grab_filename)
                with open(banner_grab_filename, 'a') as banner_log:
                    banner_to_log = "host={0}, http_port={1},\nheaders={2},\nbanner={3}\n".format(host, port,
                                                                                                  headers, banner_txt)
                    banner_log.write(banner_to_log)
                    return True
        except requests.ConnectionError:
            try:
                self.banner_grab(host, https=True)
            except Exception as error:
                logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                return False
        except Exception as error:
            logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
            return False
        except KeyboardInterrupt:
            exit(0)
        self.CONNECTION_LOCK.release()

    def http_post_xml(self, vulnerable_host, credentials):
        """ Tests for default credentials against an Web-based Authentication. Reads and POSTs data via XML files.
        This only handles one specific type of Web-based Authentication at this time.

        Args:
            vulnerable_host (object): object of the vulnerable host that will be tested.
            credentials (list): a list holding string tuples of the credentials to test.

        Returns:
            bool: True for success, False otherwise.
        """
        self.CONNECTION_LOCK.acquire()
        service = "WEB-AUTH-XML"
        if self.verbose:
            print("[*] Attempting to validate credentials via HTTP-POST...")
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

        xml_connect_path = os.path.join(self.default_filepath, "xml", "Connect.xml")

        def read_xml(xml_file):
            """ Reads the XML file to put in body of request

             Args:
                 xml_file (str): a string of the file name of the xml file to read.

            Returns:
                xml_payload (str): the xml payload to be used in the authentication process.
            """
            with open(xml_file, 'r') as xml_to_load:
                xml_payload = {"Connect.xml": xml_to_load.read()}
                return xml_payload

        # Tries to connect to host via HTTP-POST w/ the XML authentication in the body of the request.
        # Uses Regular Expressions to extract errors for debugging/tuning the program.
        try:
            for port in ports_to_check:
                connection_address = "http://{0}:{1}/xml/Connect.xml".format(host, port)
                for credential in credentials:
                    user = str(credential[0])
                    password = str(credential[1])
                    xml_body = read_xml(xml_connect_path)
                    xml_body = xml_body.replace('$username$', user)
                    xml_body = xml_body.replace('$password$', password)
                    logging.debug(xml_body)
                    logging.info("Checking {0}:{1} on {2} with {3}".format(user, password, host, service))
                    response = requests.post(connection_address, data=xml_body, headers=headers)
                    if self.verbose:
                        print(response.status_code, response.reason)
                    data = response.text
                    if "message='OK'" in data:
                        self.log_results(host, port, user, password, service)
                        vulnerable_host.put_credentials(service, port, user, password)
                        return True
                    else:
                        error_msg = re.findall(r"message='(?P<error>.*)'", str(data))
                        if error_msg:
                            error = error_msg[0]
                            if self.verbose:
                                print("[*] Server returned: {0}".format(error))
                            logging.error("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
                            return False
                        else:
                            if self.verbose:
                                print("[*] Server returned an error.")
                    response.close()
        except Exception as error:
            error_msg = re.findall(r"message='(?P<error>.*)'", str(error))
            if error_msg:
                error = error_msg[0]
                logging.exception("{0}\t{1}\t{2}".format(host, service, error))
                return False
            else:
                logging.exception("{0}\t{1}\t{2}".format(host, service, error))
                return False
        except KeyboardInterrupt:
            self.CONNECTION_LOCK.release()
            exit(0)
        self.CONNECTION_LOCK.release()

    def run_credential_test(self, hosts_to_check):
        """ Function tests hosts for default credentials on open 'admin' ports
        Utilizes threading to greatly speed up the scanning.

        Args:
            hosts_to_check (list): a list of hosts to be checked for credentials.

        Returns:
            bool: True for success, False otherwise.
        """
        service = "building_threads"
        logging.info("Building threads.")
        logging.info("Verbosity set to {0}".format(self.verbose))
        logging.info("Banner Grab variable set to {0}".format(self.banner))
        credentials_to_check = self.build_credentials()
        threads = []
        print("[*] Testing vulnerable host ip addresses...")
        try:
            for vulnerable_host in hosts_to_check:
                if self.verbose:
                    print('[*] checking >> {0}'.format(vulnerable_host.ip))
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
                    t0 = threading.Thread(target=self.http_post_xml, args=(vulnerable_host, credentials_to_check))
                    threads.append(t0)
                    if self.banner is True:
                        t1 = threading.Thread(target=self.banner_grab, args=(vulnerable_host, ))
                        threads.append(t1)
            logging.info("Starting {0} threads.".format(len(threads)))
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(120)
            return True
        except threading.ThreadError as error:
            logging.exception("{0}\t{1}".format(service, error))
            return False
        except Exception as e:
            logging.exception(e)
            return False
        except KeyboardInterrupt:
            exit(0)


def main():
    cc = CredentialChecker()
    start_time = datetime.now()
    # TODO: add resume option (read from file)
    parser = argparse.ArgumentParser(description="Check a host for login credentials.")
    parser.add_argument('--target', required=True, help='IP address to test')
    parser.add_argument('--service', required=True, help='The protocol you want to check: FTP, SSH, TELNET, HTTP-XML')
    parser.add_argument('--credentials', required=True, help='Credentials to test. Format= username:password ')
    parser.add_argument('--port', dest='http_port', type='int', help='HTTP port to test.')
    args = parser.parse_args()

    credentials = args.credenitals.split(':').strip()

    if args.service is 'FTP':
        cc.check_ftp_anon(args.target)
        cc.check_ftp(args.target, credentials)
    elif args.service is 'SSH':
        cc.check_ssh(args.target, credentials)
    elif args.service is 'TELNET':
        cc.check_telnet(args.target, 23, credentials)
    elif args.service is 'HTTP-XML':
        cc.http_post_xml(args.target, credentials)
    else:
        print("[!] Unknown service. Please use: FTP, SSH, TELNET, HTTP-XML")

    print(datetime.now() - start_time)  # Calculates run time for the program.


if __name__ == '__main__':
    main()
