import httplib
from itertools import combinations

url = '10.0.2.5'
path = "/captcha/validate?qid=799"
port = 80
captcha_to_check = []

# builds key list
keys = ["&cb0=on", "&cb1=on", "&cb2=on", "&cb3=on", "&cb4=on", "&cb5=on"]
for i in range(len(keys) + 1):
    keys_list = combinations(keys, i)
    for i in keys_list:
        key = "".join(i)
        captcha_to_check.append(path + key)

# characters_to_use = "0123456789"
# keys_to_try = product(characters_to_use, repeat=2)
# for key_pair in keys_to_try:
#     key = key_pair[0] + key_pair[1]
#     # print key


conn = httplib.HTTPConnection(url, port)
# from documentation conn.request(method, url, body, headers)
for captcha in captcha_to_check:
    try:
        conn.request("POST", captcha)
        r1 = conn.getresponse()
        data = r1.read(1000)

        print r1.status, r1.reason
        print r1.getheaders()
        print data
    except Exception:
        raise
