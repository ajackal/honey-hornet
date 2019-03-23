from unittest import TestCase
import honeyhornet.corescanner


class TestHoneyHornet(TestCase):
    def test_load_configuration_file(self):
        # skip testing standard loading of YAML config...more of an integration test at that point.
        # will test the building of a config using buildconfig
        cs = honeyhornet.corescanner.HoneyHornet()
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
        cs = honeyhornet.corescanner.HoneyHornet()
        test_target_list = ['test/test_target_list.txt']
        actual = cs.calculate_total_number_of_hosts(test_target_list)
        expected = 5
        self.assertIs(actual, expected)
        # self.fail()

    def test_calculate_number_of_hosts(self):
        # TODO: create a few live hosts and have the assert by for the correct int/float, not bool.
        cs = honeyhornet.corescanner.HoneyHornet()
        cs.create_new_vulnerable_host(['127.0.0.1'], [['22', {'port': '22', 'state': 'open'}]])
        test_target_list = ['test/test_target_list.txt']
        result = cs.calculate_number_of_hosts(test_target_list)
        self.assertTrue(result)
        # self.fail()

    def test_create_new_vulnerable_host(self):
        cs = honeyhornet.corescanner.HoneyHornet()
        result = cs.create_new_vulnerable_host(['127.0.0.1'], [['22', {'port': '22', 'state': 'open'}]])
        self.assertIsInstance(cs.vulnerable_hosts[0], honeyhornet.corescanner.VulnerableHost)
    #     self.fail()

    # def test_check_admin_ports(self):
    #     self.fail()
