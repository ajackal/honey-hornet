#!/usr/bin/env bash

if [ $(id -u) -eq 0 ]; then
    apt install vsftpd openssh-server telnetd
    useradd -m -p 38CSE0qj7d1xE devtestuser
    echo "### Credentials OK ###\n### Login Successful ###\n" > sudo tee /etc/motd
    service vsftpd restart
    service ssh restart
    service inetd restart
    python3 tests/test_http_server.py
else
    echo "Not running as root!"
fi