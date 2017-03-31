
lhosts = ['a1', 'a2', 'a3']
vhosts = []


class VulnHost(object):
    # defines hosts ip address
    # creates ports dictionary
    def __init__(self, ipaddr):
        self.ports = []
        self.p_creds = []
        self.ip = ipaddr

    # function addes open admin port to list
    def add_vport(self, port):
        self.ports.append(port)

    # ports with default credentials
    def put_creds(self, newcreds):
        self.p_creds.append(newcreds)
        return self.p_creds

    # prints the results of the test
    def get_results(self):
        # return self.ip + ';' + str(self.ports).strip('[]')
        return self.ip + ';' + str(self.p_creds)  # Checks for hosts that are alive on the network


def add_host():
    print "[*] adding hosts..."
    x = 0
    port = 23
    for lhost in lhosts:
        x += 1
        b = 'a' + str(x)  # unique class identifier
        b = VulnHost(lhost)  # adds host to class if it doesn't exist
        vhosts.append(b)  # appends vulnerable host to list
        b.add_vport(port)  # adds open port to list to check in the class
        print '[+] port : %s added.' %port


def update_list():
    for vhost in vhosts:
        host = vhost.ip
        print "[*] testing connection on {0}...".format(host)
        try:
            newcreds = host + ";21;anon"
            vhost.put_creds(newcreds)
            print "[+] update succeeded"
        except Exception as e:
            print "[!] udpate failed: {0}".format(e)


def blah():
    for vhost in vhosts:
        vhost.get_results()
        print vhost.p_creds
        with open('new-test.txt', 'a') as f:
            x = str(vhost.p_creds).strip('[]') + '\n'
            f.write(x)


def main():
    add_host()
    update_list()
    blah()



if __name__ == '__main__':
    main()