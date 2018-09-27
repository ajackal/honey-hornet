from unittest import TestCase
from honeyhornet import corescanner
from honeyhornet import credentialchecker
import os
from honeyhornet.tests import test_http_server
import threading


class TestCredentialChecker(TestCase):
    def test_build_credentials(self):
        cc = credentialchecker.CredentialChecker()
        cc.config = {'users': ['fry', 'leela', 'nibbler'], 'passwords': ['12345', 'password', 'planetExpress']}
        actual = cc.build_credentials()
        expected = [('fry', '12345'), ('fry', 'password'), ('fry', 'planetExpress'),
                    ('leela', '12345'), ('leela', 'password'), ('leela', 'planetExpress'),
                    ('nibbler', '12345'), ('nibbler', 'password'), ('nibbler', 'planetExpress')]
        self.assertListEqual(actual, expected)
        # self.fail()

    # def test_check_telnet(self):
    #     self.fail()

    # def test_check_ftp_anon(self):
    #     self.fail()
    #
    # def test_check_ftp(self):
    #     self.fail()

    def test_check_ssh(self):
        credentials = [('devtestuser', 'TestPassword123')]
        cs = corescanner.HoneyHornet()
        host = cs.create_new_vulnerable_host(['127.0.0.1', {'scan': {'127.0.0.1': {'tcp': {'9191': {'state': 'open'}}}}}], [22])
        cc = credentialchecker.CredentialChecker()
        result = cc.check_ssh(cs.vulnerable_hosts[0], credentials)
        self.assertTrue(result, msg="Integration test failed.")
    #     self.fail()

    # def test_banner_grab(self):
    #     self.fail()
    #
    def test_http_post_xml(self):
        # http_server_threat = threading.Thread(target=test_http_server.run(), daemon=True)
        # http_server_threat.start()
        # os.system("/usr/bin/python3 /home/bob/PycharmProjects/honey-hornet/honeyhornet/tests/test_http_server.py")
        credentials = [('devtestuser', 'TestPassword123')]
        cs = corescanner.HoneyHornet()
        host = cs.create_new_vulnerable_host(['127.0.0.1', {'scan': {'127.0.0.1': {'tcp': {'9191': {'state': 'open'}}}}}], [9191])
        cc = credentialchecker.CredentialChecker()
        result = cc.http_post_xml(cs.vulnerable_hosts[0], credentials)
        self.assertTrue(result, msg="Integration test failed.")
    #     self.fail()
