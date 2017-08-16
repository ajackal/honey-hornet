import re

x = "message='Invalid UserName / Password'"

m = re.findall("message=\'(?P<error>\w+\s\w+\s\/\s\w+)\'", x)

if m:
    print m[0]
else:
    print "nothing found"
