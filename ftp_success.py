from ftplib import FTP
import os
import sys

host = '127.0.0.1'

print "trying ftp connection"

retry = True
while (retry):
    try:
        f = FTP(host)
        f.connect()
        retry = False
        print "ftp port connection successful."
    except IOError as e:
        print "IOError({0}): {1}".format(e.errno, e.strerror)
        print "retrying..."
        retry = True

