import os
import tempfile

db_file = tempfile.NamedTemporaryFile()

BASE_DIR = os.getcwd()
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
LOGS_FOLDER = os.path.join(BASE_DIR, 'logs')
TOOLS_DIR = os.path.join(BASE_DIR, 'tools')
OUTPUT_DIR = os.path.join(BASE_DIR, 'reports')


class Config(object):
    SECRET_KEY = '#r$=rg*lit&!4nukg++@%k+n9#6fhkv_*a6)2t$n1b=*sadwq'


class ProdConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/mobsec.db'

    CACHE_TYPE = 'simple'


class DevConfig(Config):
    DEBUG = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False

    SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/mobsec.db'

    CACHE_TYPE = 'null'
    ASSETS_DEBUG = True
