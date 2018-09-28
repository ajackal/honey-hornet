#!/usr/bin/env bash

if [ $(id -u) -eq 0 ]; then
    apt install vsftpd openssh-server xinetd telnetd
    useradd -m -p 38CSE0qj7d1xE devtestuser
    echo "### Credentials OK ###\n### Login Successful ###\n" > sudo tee /etc/motd
    service vsftpd restart
    service ssh restart
    service xinetd restart
    python3 honeyhornet/tests/test_http_server.py &
    service --status-all
    netstat -pant
else
    echo "Not running as root!"
fi