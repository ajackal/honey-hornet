#! /usr/bin/env python

import telnetlib
import optparse
import time
from datetime import datetime


TIMER_DELAY = 3


def check_telnet(host, port, user, password):
    """ Tries to connect via Telnet with common credentials
    Then it prints the results of the connection attempt
    Due to the way TELNETLIB works and the different implementations of telnet
    This is fairly inefficient way to test credentials
    Really needs to be customized based on the telnet implementation
    Web-based credential testing is much better and more standardized

    UPDATE: Found that using a time.sleep() pause is a much more effective way of
    inputing credentials when testing. Generally, an "OK" response is received
    almost immediately when the correct credentials are supplied. When the wrong
    credentials are supplied, the repsone is much more delayed. A 3 second timeout
    has been effective.
    """
    try:
        print "[*] Testing Telnet connection on {0}...".format(host)
        # print "[*] username: {0} password: {1} port: {2}".format(user, password, port)
        t = telnetlib.Telnet(host, port, 15)
        # output = t.read_eager()
        # print output
        # t.read_until("login:")
        time.sleep(TIMER_DELAY)
        t.write(user + "\r\n")
        # t.read_until("Password:")
        time.sleep(TIMER_DELAY)
        t.write(password + "\r\n")
        time.sleep(TIMER_DELAY)
        server_response = t.read_very_eager()
        # print server_response
        if "OK" in server_response:
            protocol = "telnet"
            log_results(host, port, user, password, protocol)
            t.close()
        elif "incorrect" in server_resposne:
            log_error("Password incorrect.")
            t.close()
        else:
            t.close()
    except Exception as error:
        log_error(error)


def log_results(host, port, user, password, protocol):
    """ Logs credentials that are successfully recovered. """
    time_now = str(datetime.now())
    print "[*] Recording successful attempt:"
    event = " host='{0}', port={1}, user='{2}', password='{3}', protocol='{4}'\n".format(host, port, user, password,
                                                                                         protocol)
    print "[*] Password recovered:{0}".format(event)
    with open("recovered_passwords.log", 'a') as log_file:
        log_file.write(time_now)
        log_file.write(event)


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

    parser = optparse.OptionParser('usage: %prog <scan type> <targets> <options>')
    parser.add_option('-i', dest='ifile', type='string', help='import IP addresses from file, cannot be used with -c')
    parser.add_option('-u', dest='user', type='string', help='imports users from file; else: uses default list')
    parser.add_option('-p', dest='password', type='string', help='imports passwords from file; else: uses default list')
    parser.add_option('-o', dest='port', type='string', help='import ports from file')

    (options, args) = parser.parse_args()
    ifile = options.ifile
    user = options.user
    password = options.password
    port = options.port

    with open(ifile, 'r') as user_file:
        vulnerable_hosts = user_file.read().splitlines()
    try:
        for host in vulnerable_hosts:
            check_telnet(host, port, user, password)
    except Exception:
        raise
    finally:
        print datetime.now() - start_time


if __name__ == "__main__":
    main()

