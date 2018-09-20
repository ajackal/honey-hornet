from unittest import TestCase
from honeyhornet import logger


class TestHoneyHornetLogger(TestCase):
    def test_write_log_file(self):
        test_log_file = logger.HoneyHornetLogger()
        event = "A test event."
        wrong_event = "Something different so it fails."
        test_log_file.write_log_file(test_log_file.log_name, event)
        with open(test_log_file.log_name, 'r') as log_file_open:
            self.assertIn(event, log_file_open.read())
        # self.fail()
