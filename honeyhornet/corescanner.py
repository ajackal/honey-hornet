import argparse
import logging
import os
import sys
import nmap
import yaml
import json
from datetime import datetime, date
from termcolor import colored
from credentialchecker import CredentialChecker
from viewchecker import ViewChecker
from logger import HoneyHornetLogger
import buildconfig


class HoneyHornet(HoneyHornetLogger):
    """
    Uses NMAP to scan the targets and ports listed in the configuration file.

    Inherits HoneyHornet Logger for all the logging functionality.

    Attributes:
        - vulnerable_hosts(list) = list of all the vulnerable hosts found during the scan
        - live_hosts(list) = all live hosts that are found
        - time_stamp(str) = used for creating file names
        - verbose(boolean) = set to True for more verbose print statements through execution
        - default_filepath(str) = gets the current working directory to generate absolute file paths
        - default_config_filepath(str) = the default file path to the config file
        - config(dict) = YAML configuration gets loaded here
    """

    vulnerable_hosts = []

    def __init__(self):
        HoneyHornetLogger.__init__(self)
        self.live_hosts = []
        self.time_stamp = str(date.today())
        self.verbose = False
        self.default_filepath = os.path.dirname(os.getcwd())
        self.default_config_filepath = os.path.join(self.default_filepath, "configs", "config.yml")
        self.config = {}

    def load_configuration_file(self, yml_config):
        """Loads the YAML configuration file needed to run the program.

        Use command line option "--config" to load a specific file.
        Will load "config.yml" in the "configs/" directory by default.

        Args:
            - yml_config(str): the YAML configuration file you want to load.

        Returns:
            - config(dict): variable containing all the configuration settings.
        """
        try:
            with open(yml_config, 'r') as cfg_file:
                self.config = yaml.load(cfg_file)
        except IOError:
            b = buildconfig.BuildConfig()
            self.load_configuration_file(self.default_config_filepath)

    def write_results_to_csv(self):
        """Writes the results of the scan to a CSV formatted file.

        Args:
            - None

        Returns:
            - Nothing
        """
        results_file = self.time_stamp + "_recovered_passwords.csv"
        results_file = os.path.join(self.default_filepath, "reports", results_file)
        headers = "Time Stamp,IP Address,Service,Port,Username,Password\n"
        with open(results_file, 'a') as open_csv:
            open_csv.write(headers)
            for host in self.vulnerable_hosts:
                host.get_credentials(open_csv)

    def write_results_to_json(self):
        """Writes the results of the scan to a JSON formatted file.

        Args:
            - None

        Returns:
            - Nothing
        """
        results_file = self.time_stamp + "_saved_objects.json"
        results_file = os.path.join(self.default_filepath, "saves", results_file)
        with open(results_file, 'a') as open_json_file:
            for host in self.vulnerable_hosts:
                to_json = {'host': host.ip, 'ports': host.ports, 'credentials': host.credentials}
                open_json_file.write(json.dumps(to_json))
                open_json_file.write("\n")

    def log_open_port(self, host, port, status):
        """ Logs any host with an open port to a custom formatted log file.

        Args:
            - host(str) = IP Address of the host with an open port
            - port(str) = the open port that was found
            - status(str) = always 'open'

        Returns:
            - Nothing

        """
        logfile_name = str(date.today()) + "_open_ports.log"
        logfile_name = os.path.join(self.default_filepath, "logs", logfile_name)
        event = " host={0}   \tport={1}  \tstatus={2}".format(colored(host, "green"),
                                                              colored(port, "green"),
                                                              colored(status, "green"))
        if self.verbose:
            print("[*] Open port found:{0}".format(event))
        self.write_log_file(logfile_name, event)
        self.write_log_file(logfile_name, "\n")

    def calculate_total_number_of_hosts(self, target_list):
        """ Calculates the total number of hosts that will be scanned.

        Args:
            - target_list(list) = a single item list returned from loading the YAML configuration

        Returns:
            - total(int) = the total number of hosts in the target list
        """
        target_list = str(target_list).strip("['']")
        target_list = os.path.join(self.default_filepath, "targets", target_list)
        with open(target_list, 'r') as open_target_list:
            return len(open_target_list.readlines())

    def calculate_number_of_hosts(self, target_list):
        """ Calculates the number of a live hosts and the open percentage.

        Args:
            - target_list(list) = a single item list returned from loading the YAML configuration

        Returns:
            - writes to results to a log file and prints to screen
        """
        try:
            total = self.calculate_total_number_of_hosts(target_list)
            live = len(self.vulnerable_hosts)
            percentage = 100 * (float(live) / float(total))
            print("\n[+] {0} out of {1} hosts are vulnerable or {2}%".format(live, total, round(percentage, 2)))
            logfile_name = str(date.today()) + "_open_ports.log"
            logfile_name = os.path.join(self.default_filepath, "logs", logfile_name)
            with open(logfile_name, 'a') as log_file:
                new_log = "##############  SCAN RESULTS  ##############\n"
                log_file.write(new_log)
                log_totals = "{0}\{1} = {2}%\n".format(live, total, round(percentage, 2))
                log_file.write(log_totals)
        except Exception as error:
            logging.exception("calculate_number_of_hosts\t{0}".format(error))

    def create_new_vulnerable_host(self, host, ports):
        """ Instantiates a new object of the Vulnerable host """
        new_host = VulnerableHost(host[0])  # creates new object
        self.vulnerable_hosts.append(new_host)
        for port in ports:
            port_state = port[1]['state']  # defines port state variable
            if port_state == 'open':  # checks to see if status is open
                new_host.add_vulnerable_port(port[0])
                self.log_open_port(host[0], port[0], port_state)

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
            scanner = nmap.PortScannerYield()  # defines port scanner function
            print("[*] checking for open admin ports...")
            targets = '-iL ' + os.path.join(self.default_filepath, "targets", str(target_list).strip('[]'))
            ports = ' -Pn -p ' + str(ports_to_scan).strip('[]').replace(' ', '')
            total_hosts = self.calculate_total_number_of_hosts(target_list)
            counter = 0
            for host in scanner.scan(hosts=targets, arguments=ports): # Nmap scan command
                counter += 1
                percentage = float(counter) / float(total_hosts) * 100.0
                percentage = int(percentage)
                sys.stdout.write('\r')
                sys.stdout.write("[%-100s] %d%% Currently on %s" % ('='*percentage, percentage, host[0]))
                sys.stdout.flush()
            # hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
            # for host, status in hosts_list:
                try:
                    ports = host[1]['scan'][host[0]]['tcp'].viewitems()  # retrieves tcp port results from scan
                    self.create_new_vulnerable_host(host, ports)
                except KeyError:
                    continue
        # except scanner.PortScannerError as error:
        #     print "[!] Error running port scanner, check target list path."
        #     logging.exception("{0}\t{1}".format(service, error))
        #     exit(0)
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
        new_credentials = {"user": user, "password": password, "port": port, "service": service}
        self.credentials.update(new_credentials)

    def put_banner(self, port, banner_txt, status, reason, headers):
        """ Adds port, banner to banner list of a port that is defined in the http_ports list or is not handled
         by another service check.
         """
        self.banner.append(':{0} {1} {2} {3}\n{4}\n'.format(port, status, reason, banner_txt, headers))

    def get_credentials(self, open_csv):
        """ Formats and writes recovered credentials to a CSV file. """
        x = len(self.credentials)
        for credential in self.credentials:
            open_csv.write("{0},{1},{2},{3},{4},{5}\n".format(self.time_stamp, self.ip,
                                                              self.credentials['service'],
                                                              self.credentials['port'],
                                                              self.credentials['user'],
                                                              self.credentials['password']))


def main():
    """ Main program """
    start_time = datetime.now()
    # TODO: add resume option (read from file)

    # Honey Hornet switches
    parser = argparse.ArgumentParser(description="Run a port scan or test credentials.")
    parser.add_argument('--config', help='Define which config file to use.')
    args = parser.parse_args()

    # Instantiates HoneyHornet & loads the appropriate config file.
    hh = HoneyHornet()
    if args.config is None:
        hh.load_configuration_file(os.path.join(hh.default_filepath, "configs", "config.yml"))
    else:
        if "config/" in args.config:
            hh.load_configuration_file(args.config)
        else:
            config_to_run = os.path.join(hh.default_filepath, "configs", args.config)
            hh.load_configuration_file(config_to_run)

    # Setup local variables based on the config file.
    if args.config:
        print("[*] Using {0} YAML config file...".format(colored(args.config, 'yellow')))
    else:
        print("[*] Using {0} YAML config file...".format(colored('default', 'yellow')))
    target_hosts = hh.config['targets']
    ports_to_scan = hh.config['ports']
    scan_type = str(hh.config['scanType']).strip('[]')
    banner = hh.config['bannerGrab']
    results_format = hh.config['resultsFormat']

    # Selects the type of scan to run based on the config.
    service = "run_scan_type"
    try:
        if scan_type == '1':
            print("[*] Running in port scanner mode...")
            hh.check_admin_ports(target_hosts, ports_to_scan)
            print("[*] Finishing up & exiting...")
        elif scan_type == '2':
            print("[*] Running in credential check mode...")
            # Instantiates Credential Checker & loads the HoneyHornet config.
            cc = CredentialChecker(config=hh.config)
            # Enables banner grabbing if True in config.
            if banner is True:
                cc.banner = banner
            hh.check_admin_ports(target_hosts, ports_to_scan)
            hh.calculate_number_of_hosts(target_hosts)
            hosts_to_check = hh.vulnerable_hosts
            cc.run_credential_test(hosts_to_check)
            print("[*] Finishing up & exiting...")
        elif scan_type == '3':
            print("[*] Running in view check mode...")
            vc = ViewChecker(config=hh.config)
            hh.check_admin_ports(target_hosts, ports_to_scan)
            hosts_to_check = hh.vulnerable_hosts
            vc.run_view_checker(hosts_to_check)
            print("[*] Finishing up & exiting...")
        else:
            print("[!] Please define a scan type in config file!")
            exit(0)
    except KeyboardInterrupt:
        exit(0)
    except Exception as error:
        logging.exception("{0}\t{1}".format(service, error))
    finally:
        print("Runtime is: " + str(datetime.now() - start_time))  # Calculates run time for the program.
        if 'csv' in results_format:
            hh.write_results_to_csv()
        if 'json' in results_format:
            hh.write_results_to_json()
        exit(0)


if __name__ == "__main__":
    main()
