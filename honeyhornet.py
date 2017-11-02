#! /usr/bin/env python

import credentialchecker
import logging
from threading import BoundedSemaphore
from datetime import datetime, date
from termcolor import colored
import nmap
import yaml
import csv
import json

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
        self.time_stamp = str(date.today())
        self.users = []  # users that will be tested
        self.passwords = []  # passwords to be tested
        self.verbose = False  # if there will be a verbose output, default=False
        self.banner = False  # if we should do a banner grab, default=False
        # TODO: add the ability for a user to define custom YAML config file.
        with open('config.yml', 'r') as cfg_file:
            self.config = yaml.load(cfg_file)

    def add_banner_grab(self, banner):
        self.banner = banner

    def write_results_to_csv(self):
        results_file = self.time_stamp + " Recovered_Passwords.csv"
        headers = "Time Stamp,IP Address,Service,Port,Username,Password"
        with open(results_file, 'a') as open_csv:
            csvwriter = csv.writer(open_csv)
            csvwriter.writerow(headers)
            for vulnerable_host in self.vulnerable_hosts:
                vulnerable_host.get_credentials(csvwriter)

    def write_results_to_json(self):
        results_file = self.time_stamp + " Recovered_Passwords.json"
        with open(results_file, 'a') as open_json:
            for vulnerable_host in self.vulnerable_hosts:
                open_json.write(json.dumps(vulnerable_host.__dict__))

    @staticmethod
    def write_log_file(logfile_name, event):
        """ Writes the event to the proper log file """
        time_now = datetime.now()
        with open(logfile_name, 'a') as log_file:
            log_file.write(str(time_now))
            log_file.write(event)

    def log_open_port(self, host, port, status):
        """ Logs any host with an open port to a file. """
        logfile_name = str(date.today()) + "_open_ports.log"
        event = " host={0}\tport={1}  \tstatus='{2}'\n".format(host, port, status)
        print "[*] Open port found:{0}".format(event)
        self.write_log_file(logfile_name, event)

    # TODO: Add INFO level logging

    def calculate_number_of_hosts(self, target_list):
        """ Function scans the list or CIDR block to see which hosts are alive
        writes the live hosts to the 'live_hosts' list
        also calculates the percentage of how many hosts are alive
        """
        print "[*] scanning for live hosts..."
        try:
            # TODO: check the target_list, if string, .split(','), else just len()
            if type(target_list) is str:
                total = len(target_list.split(','))
            else:
                total = len(target_list)
            live = len(self.vulnerable_hosts)
            percentage = 100 * (float(live) / float(total))
            print "[+] {0} out of {1} hosts are vulnerable or {2}%".format(live, total, percentage)
            with open("open_ports.log", 'a') as log_file:
                new_log = "##############  NEW SCAN  ##############\n"
                log_file.write(new_log)
                log_totals = "{0}\{1} = {2}%\n".format(live, total, percentage)
                log_file.write(log_totals)
        except Exception as error:
            logging.exception("calculate_number_of_hosts\t{0}".format(error))

    def check_admin_ports(self, target_list, ports_to_scan):
        """Scans for a live host and for any open common admin ports defined in the configuration file.
        If an open port is found, it instantiates a class for that host and records all the open ports.

        Tests all live host for open 'admin' ports

        Changed to let NMAP handling the threading. Had implemented threading, but threading NMAP,
        which is threaded seems to add complications. New implementation is very fast and almost no issues.

        Ports list as argument needed to have the whitespace stripped between each port, otherwise the NMAP command
        is not constructed properly.
        """

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
            logging.exception("{0}\t{1}".format(service, error))
        except KeyboardInterrupt:
            exit(0)


class VulnerableHost(HoneyHornet):
    """ Defines a class for each live host with an open admin port and saves the open ports to a list. These objects
     are then used when the CredentialChecker() class is instantiated and services checked.
     """
    def __init__(self, ipaddr):
        HoneyHornet.__init__(self)
        self.ports = []
        self.credentials = {}
        self.banner = []
        self.ip = ipaddr

    def add_vulnerable_port(self, port):
        """ Function appends open admin port to list. """
        self.ports.append(port)

    def put_credentials(self, service, port, user, password):
        """ Records credentials of a successful login attempt to an open admin port. """
        credential_index = service + str(port)
        self.credentials[credential_index] = {}
        new_credentials = {}
        new_credentials.update(user=user, password=password, port=port, service=service)
        self.credentials[credential_index].update(new_credentials)

    def put_banner(self, port, banner_txt, status, reason, headers):
        """ Adds port, banner to banner list of a port that is defined in the http_ports list or is not handled
         by another service check.
         """
        self.banner.append(':{0} {1} {2} {3}\n{4}\n'.format(port, status, reason, banner_txt, headers))

    def get_credentials(self, csvwriter):
        """ Formats and writes recovered credentials to a CSV file. """
        for credential in self.credentials:
            csvwriter.writerow("{0},{1},{2}".format(self.time_stamp, self.ip, self.credentials[credential].values()))


def main():
    """ Main program """
    start_time = datetime.now()
    # TODO: add resume option (read from file)

    log_name = str(date.today()) + " DEBUG.log"
    logging.basicConfig(filename=log_name, format='%(asctime)s %(levelname)s: %(message)s',
                        level=logging.DEBUG)
    
    hh = HoneyHornet()
    cc = credentialchecker.CredentialChecker()

    print "[*] Using default YAML config file..."
    target_hosts = hh.config['targets']
    ports_to_scan = hh.config['ports']
    scan_type = str(hh.config['scanType']).strip('[]')
    banner = hh.config['bannerGrab']
    results_format = hh.config['resultsFormat']

    if banner is True:
        cc.add_banner_grab(banner)

    service = "run_scan_type"
    try:
        if scan_type == '1':
            print "[*] Running in port scanner mode..."
            hh.check_admin_ports(target_hosts, ports_to_scan)
            print "[*] Finishing up & exiting..."
        elif scan_type == '2':
            print "[*] Running in credential check mode..."
            hh.check_admin_ports(target_hosts, ports_to_scan)
            hh.calculate_number_of_hosts(target_hosts)
            hosts_to_check = hh.vulnerable_hosts
            cc.run_credential_test(hosts_to_check)
            print "[*] Finishing up & exiting..."
        else:
            print "[!] Please define a scan type in config file!"
            exit(0)
    except KeyboardInterrupt:
        exit(0)
    except Exception as error:
        logging.exception("{0}\t{1}".format(service, error))
    finally:
        print "Runtime is: " + str(datetime.now() - start_time)  # Calculates run time for the program.
        if 'csv' in results_format:
            hh.write_results_to_csv()
        if 'json' in results_format:
            hh.write_results_to_json()
        exit(0)


if __name__ == "__main__":
    main()
