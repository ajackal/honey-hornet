import re

xml_connect = "xml/Connect.xml"

def get_pass_from_xml():
    with open(xml_connect) as f:
        x = f.read()
        m = re.findall("CDATA\[(?P<password>\w*)\]", x)
        if m:
            password = m[0]
            print password
            return password
        else:
            print "nothing found"
        # print password
        # return password

get_pass_from_xml()
