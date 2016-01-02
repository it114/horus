import os
import logging
from webapp.settings import LOGS_FOLDER

# create logger
logger = logging.getLogger('horus')
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create a file handler
file_log = logging.FileHandler(os.path.join(LOGS_FOLDER, 'app.log'))

# create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)
file_log.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)
