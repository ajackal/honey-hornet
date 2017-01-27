class VulnHost:

    ports = []

    def __init__(self, ip):
        self.ip = ip

    def add_host(self, vport):
        self.ports.append(vport)


# t = VulnHost('192.168.1.1')
# t.add_host('23')

# print "host is ", t.ip
# print "open admin ports are ", t.ports

hosts = [1, 2, 3, 4]
x = 0
for host in hosts:
    x +=1 
    b = 'a' + str(x)
    print b
    b = VulnHost(host)
    b.add_host('23')
    print b.ip
    print b.ports
