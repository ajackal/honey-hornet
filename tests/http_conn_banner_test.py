import httplib
from itertools import product

# builds key list
characters_to_use = "0123456789"
keys_to_try = product(characters_to_use, repeat=2)

for key_pair in keys_to_try:
    key = key_pair[0] + key_pair[1]
    # print key

url = 'http://10.0.2.5'
port = 80

conn = httplib.HTTPConnection(url, port)
# from documentation conn.request(method, url, body, headers)
conn.request("GET", "/")

r1 = conn.getresponse()
data = r1.read(1000)

print r1.status, r1.reason
print r1.getheaders()
print data
