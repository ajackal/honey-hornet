import os
import logging
from datetime import date, datetime


class HoneyHornetLogger:
    def __init__(self):
        # Setup logging file path and formatting
        log_name = "../logs/" + str(date.today()) + "_DEBUG.log"
        log_directory = os.path.dirname(log_name)
        if not os.path.exists(log_directory):
            os.mkdir(log_directory)
        logging.basicConfig(filename=log_name, format='%(asctime)s %(levelname)s: %(message)s',
                            level=logging.DEBUG)

    @staticmethod
    def write_log_file(logfile_name, event):
        """ Writes the event to the proper log file """
        time_now = datetime.now()
        with open(logfile_name, 'a') as log_file:
            if "\n" not in event:
                log_file.write(str(time_now))
            log_file.write(event)