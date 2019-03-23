import os
import argparse
from logger import HoneyHornetLogger
from threading import BoundedSemaphore
import threading
import logging
from datetime import date, datetime
from termcolor import colored
import http.client
import re
import time


class ViewChecker(HoneyHornetLogger):
    def __init__(self, config=None):
        HoneyHornetLogger.__init__(self)
        self.config = config
        self.verbose = False
        self.banner = False
        MAX_CONNECTIONS = 20  # max threads that can be created
        self.CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTIONS)
        self.TIMER_DELAY = 3  # timer delay used for Telnet testing
        self.default_filepath = os.path.dirname(os.getcwd())
        log_name = str(date.today()) + "_DEBUG.log"
        log_name = os.path.join(self.default_filepath, "logs", log_name)
        logging.basicConfig(filename=log_name, format='%(asctime)s %(levelname)s: %(message)s',
                            level=logging.DEBUG)

    def determine_camera_model(self, vulnerable_host, https=False, retry=False):
        """ simple banner grab with http.client """
        ports = []
        self.CONNECTION_LOCK.acquire()
        service = "DETERMINE-CAMERA-MODEL"
        if retry is False:
            try:
                host = vulnerable_host.ip
                ports_to_check = set(vulnerable_host.ports)
            except vulnerable_host.DoesNotExist:
                host = str(vulnerable_host)
                ports_to_check = set(ports.split(',').strip())
        elif retry is True:
            host = vulnerable_host
        if self.verbose:
            print("[*] Checking camera make & model of {0}".format(host))
        logging.info('{0} set for {1} service'.format(host, service))
        try:
            for port in ports_to_check:
                if https is True:
                    conn = http.client.HTTPSConnection(host, port)
                else:
                    conn = http.client.HTTPConnection(host, port)
                conn.request("GET", "/")
                http_r1 = conn.getresponse()
                camera_check = http_r1.read(1024)
                headers = http_r1.getheaders()
                if self.verbose:
                    print(http_r1.status, http_r1.reason)
                print(http_r1.status, http_r1.reason)
                results = re.findall(r"<title>(?P<camera_title>.*)</title>", str(camera_check))
                if results:
                    print(results)
                else:
                    print("No match for <Title> tag found.")
                # puts banner into the class instance of the host
                # vulnerable_host.put_banner(port, banner_txt, http_r1.status, http_r1.reason, headers)
                # banner_grab_filename = str(date.today()) + "_banner_grabs.log"
                # banner_grab_filename = os.path.join(self.default_filepath, "logs", banner_grab_filename)
                # with open(banner_grab_filename, 'a') as banner_log:
                #     banner_to_log = "host={0}, http_port={1},\nheaders={2},\nbanner={3}\n".format(host, port,
                #                                                                                   headers, banner_txt)
                #     banner_log.write(banner_to_log)
        except http.client.HTTPException:
            try:
                self.determine_camera_model(host, https=True, retry=True)
            except Exception as error:
                logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
        except Exception as error:
            if error[0] == 104:
                self.determine_camera_model(host, https=True, retry=True)
            logging.exception("{0}\t{1}\t{2}\t{3}".format(host, port, service, error))
        except KeyboardInterrupt:
            exit(0)
        self.CONNECTION_LOCK.release()

    def run_view_checker(self, hosts_to_check):
        """ 
        Function tests hosts for default credentials on open 'admin' ports
        Utilizes threading to greatly speed up the scanning
        """
        service = "building_threads"
        logging.info("Building threads.")
        logging.info("Verbosity set to {0}".format(self.verbose))
        threads = []
        print("[*] Testing vulnerable host ip addresses...")
        try:
            for vulnerable_host in hosts_to_check:
                if self.verbose:
                    print('[*] checking >> {0}'.format(vulnerable_host.ip))
                if set(vulnerable_host.ports):
                    t0 = threading.Thread(target=self.determine_camera_model, args=(vulnerable_host, ))
                    threads.append(t0)
            logging.info("Starting {0} threads.".format(len(threads)))
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(120)
        except KeyboardInterrupt:
            exit(0)
        except threading.ThreadError as error:
            logging.exception("{0}\t{1}".format(service, error))
        except Exception as e:
            logging.exception(e)
    