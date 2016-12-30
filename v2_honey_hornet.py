from nmap import nmap


lhosts = []  # live hosts
commonAdminPorts = [21, 22, 23, 25, 80, 135, 443, 3389]

nm = nmap.PortScanner()
nm.scan(hosts='192.168.1.0/24', arguments='-sn')
hosts_list = [(x,nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
    print('{0}:{1}'.format(host,status))
    lhosts.append(host)
    lport = nm[host]['tcp'].keys()
    lport.sort()
    for lport in lports:
        print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))   
#   nm.scan(hosts=host, arguments="-sT -p '21,22,23,25,80,135,443,3389'")
#   print nm[host]['tcp'][port]['state']

# for lhost in lhosts:
#    for commonAdminPort in commonAdminPorts:
#        oport = nm[lhost]['tcp'][commonAdminPort]['state']
#        print oport
#        nm.scan(hosts=lhost, arguments='-sT -p' + str(commonAdminPort)
#        print 'port: {0} is {1}'.format(portid, state)

