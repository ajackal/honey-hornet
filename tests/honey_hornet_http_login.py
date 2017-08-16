#! /usr/bin/env python

import httplib, urllib
import sys
import re

port = sys.argv[2]


headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",\
"Content-Type": "text/xml", \
"Accept": "application/xml, text/xml, */*; q=0.01", \
"Accept-Language": "en-US,en;q=0.5", \
# "Referrer": "http://{0}:{1}".format(host, port), \
"X-Requested-With": "XMLHttpRequest", \
"Connection": "close"}
body_public = '/xml/GetPublic.xml'
body_connect = '/xml/Connect.xml'

xml_public = "xml/Public.xml"
xml_connect = "xml/Connect.xml"


def get_pass_from_xml():
    with open(xml_connect) as f:
        x = f.read()
        m = re.findall("CDATA\[(?P<password>\w*)\]", x)
        if m:
            password = m[0]
            print password
            return password
        else:
            print "nothing found"


def read_xml(xml_file):
    with open(xml_file, 'r') as f:
        xml = f.read()
        return xml

def post_credentials(host):
    try:
        conn = httplib.HTTPConnection(host, port)
        print "[*] Attempting to validate credentials via HTTP-POST..."
        method = "HTTP-POST"
        xml = read_xml(xml_connect)
        conn.request("POST", body_connect, xml, headers)
        response = conn.getresponse()
        print response.status, response.reason
        data = response.read()
        if "message='OK'" in data:
            password = get_pass_from_xml()
            rec_results(host, port, password, method)
        else:
            print "[*] Server returned: {0}".format(data)
        conn.close()
    except Exception as e:
        rec_error(host, port, method, e)
        print


def get_host_list():
    host_list_file = sys.argv[1]
    with open(host_list_file, 'r') as f:
        host_list = f.readlines()
        host_list = [i.strip('\r\n') for i in host_list]
    return host_list

def run_credential_check():
    hosts = get_host_list()
    for host in hosts:
        post_credentials(host)


def rec_error(host, port, method, e):
    print "[*] Recording error:"
    event = "[*] Error raised: host={0},port={1},method={2},error={3}".format(host, port, method, e)
    print event
    with open("error.log", 'a') as f:
        f.write(event)


def rec_results(host, port, password, method):
    print "[*] Recording successful attempt:"
    event = "[*] Password recovered: host={0},port={1},password={2},method={3}".format(host, port, password, method)
    print event
    with open("recovered_passwords.log", 'a') as f:
        f.write(event)


def main():
    run_credential_check()


if __name__ == '__main__':
    main()
