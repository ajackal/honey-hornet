from unittest import TestCase
from honeyhornet import corescanner


class TestHoneyHornet(TestCase):
    def test_load_configuration_file(self):
        # skip testing standard loading of YAML config...more of an integration test at that point.
        # will test the building of a config using buildconfig
        cs = corescanner.HoneyHornet()
        yml_config = "aNon-existentYAMLconfig.yml"
        yml_config = "/home/Chris/Projects/honey-hornet/configs/config.yml"
        expected = "built"
        actual = cs.load_configuration_file(yml_config)
        self.assertIn(expected, actual)
        # self.fail()

    def test_write_results_to_csv(self):
        self.fail()

    def test_write_results_to_json(self):
        self.fail()

    def test_log_open_port(self):
        self.fail()

    def test_calculate_total_number_of_hosts(self):
        self.fail()

    def test_calculate_number_of_hosts(self):
        self.fail()

    def test_create_new_vulnerable_host(self):
        self.fail()

    def test_check_admin_ports(self):
        self.fail()
