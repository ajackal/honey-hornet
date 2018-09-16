from unittest import TestCase
from honeyhornet import corescanner
from honeyhornet import logger
import os


class TestHoneyHornet(TestCase):
    def test_load_configuration_file(self):
        # skip testing standard loading of YAML config...more of an integration test at that point.
        # will test the building of a config using buildconfig
        cs = corescanner.HoneyHornet()
        yml_config = "aNon-existentYAMLconfig.yml"
        # real_yml_config = os.path.join(os.getcwd(),"configs", "config.yml")
        result = cs.load_configuration_file(yml_config)
        self.assertFalse(result)
        # self.fail()

    # def test_write_results_to_csv(self):
    #     self.fail()

    # def test_write_results_to_json(self):
    #     self.fail()

    # def test_log_open_port(self):
    #     self.fail()

    def test_calculate_total_number_of_hosts(self):
        cs = corescanner.HoneyHornet()
        test_target_list = ['test/test_target_list.txt']
        actual = cs.calculate_total_number_of_hosts(test_target_list)
        expected = 5
        self.assertIs(actual, expected)
        # self.fail()

    def test_calculate_number_of_hosts(self):
        # TODO: create a few live hosts and have the assert by for the correct int/float, not bool.
        cs = corescanner.HoneyHornet()
        test_log_file = logger.HoneyHornetLogger()
        test_target_list = ['test/test_target_list.txt']
        result = cs.calculate_number_of_hosts(test_target_list)
        self.assertTrue(result)
        # self.fail()

    # def test_create_new_vulnerable_host(self):
    #     self.fail()

    # def test_check_admin_ports(self):
    #     self.fail()
