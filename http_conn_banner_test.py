import httplib


url = raw_input('url to connect to: ')

conn = httplib.HTTPConnection(url, 9191)
conn.request("GET", "/")

r1 = conn.getresponse()
data = r1.read(1000)

print r1.status, r1.reason
print data

