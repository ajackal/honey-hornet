
lhosts = ['a1', 'a2', 'a3']
vhosts = []


class VulnHost(object):
    # creates initial 2 lists
    def __init__(self, ipaddr):
        self.ports = []
        self.p_creds = []
        self.ip = ipaddr

    # function adds a port to list
    def add_vport(self, port):
        self.ports.append(port)

    # ports with default 'credentials'
    def put_creds(self, newcreds):
        self.p_creds.append(newcreds)
        return self.p_creds

    # prints the results of the test
    def get_results(self):
        # return self.ip + ';' + str(self.ports).strip('[]')  # only returns the init list, not the modifications
        return self.ip + ';' + str(self.p_creds)  # same as above

def add_host():
    print "[*] adding hosts..."
    x = 0
    port = 23
    for lhost in lhosts:
        x += 1
        b = 'a' + str(x)  # unique class identifier
        b = VulnHost(lhost)  # adds host to class
        vhosts.append(b)  # appends vulnerable host to list
        b.add_vport(port)  # adds open port to list to check in the class
        print '[+] port : %s added.' %port


# adds one set of values to the list credentials
def update_list():
    for vhost in vhosts:
        host = vhost.ip
        print "[*] testing connection on {0}...".format(host)
        try:
            newcreds = host + ";21;anon"
            vhost.put_credentials(newcreds)
            print "[+] update succeeded"
        except Exception as e:
            print "[!] udpate failed: {0}".format(e)


# adds a second value to the same credentials list
def update_list2():
    for vhost in vhosts:
        host = vhost.ip
        print "[*] testing connection on {0}...".format(host)
        try:
            newcreds = host + ";23;bob;password1"
            vhost.put_credentials(newcreds)
            print "[+] update succeeded"
        except Exception as e:
            print "[!] udpate failed: {0}".format(e)


# prints the credentials list to stdout and a file
def blah():
    for vhost in vhosts:
        vhost.get_results()  # returns nothing (init value)
        print vhost.p_creds  # returns correct values
        # writes correct values to file
        # try inserting this to a class method??
        with open('new-test.txt', 'a') as f:
            x = str(vhost.p_creds).strip('[]') + '\n'  # assigns credentials to x, correctly
            f.write(x)  # writes x to file, also correctly


def main():
    add_host()
    update_list()
    update_list2()
    blah()


if __name__ == '__main__':
    main()
