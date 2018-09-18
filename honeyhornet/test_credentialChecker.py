from unittest import TestCase
from honeyhornet import credentialchecker


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
    #
    # def test_check_ssh(self):
    #     self.fail()
    #
    # def test_banner_grab(self):
    #     self.fail()
    #
    # def test_http_post_xml(self):
    #     self.fail()
