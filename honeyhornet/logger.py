import os
import logging
from datetime import date, datetime


class HoneyHornetLogger:
    """"Logging class that handles all logging for the entire application.

    Attributes:
        log_directory (str): the full file path of the logging directory.
        log_filename (str): the file name for the log file.
        log_name (str): full file path and file name of the log file.
    """
    def __init__(self):
        """ Setup logging file path and formatting """
        self.log_directory = os.path.join(os.path.dirname(os.getcwd()), "logs")
        self.log_filename = str(date.today()) + "_DEBUG.log"
        self.log_name = os.path.join(self.log_directory, self.log_filename)
        # self.log_directory = os.path.dirname(log_name)
        if not os.path.exists(self.log_directory):
            os.mkdir(self.log_directory)
        logging.basicConfig(filename=self.log_filename, format='%(asctime)s %(levelname)s: %(message)s',
                            level=logging.DEBUG)

    def write_log_file(self, event):
        """ Writes the event to the proper log file.

         Args:
             event (str): the event to be written to the log file
        """
        time_now = datetime.now()
        with open(self.log_name, 'a') as log_file:
            if "\n" not in event:
                log_file.write(str(time_now))
            log_file.write(event)
