hosts = ["a", "b", "c", "d"]
ports = ["1", "2", "3", "4"]

for host in hosts:
    x = 0
    while x < len(ports):
        print host + ports[x]
        x += 1

