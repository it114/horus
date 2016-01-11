import os
from tornado.options import define

BASE_DIR = os.getcwd()
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
LOGS_FOLDER = os.path.join(BASE_DIR, 'logs')
TOOLS_DIR = os.path.join(BASE_DIR, 'tools')
OUTPUT_DIR = os.path.join(BASE_DIR, 'reports')

define("port", default=5000, help="run on the given port", type=int)
define("config", default=None, help="tornado config file")
define("debug", default=True, help="debug mode")

settings = {}

settings["debug"] = True
settings["cookie_secret"] = "askdfjpo83q47r9haskldfjh8"
#settings["login_url"] = "/login"
settings["static_path"] = os.path.join(os.path.dirname(__file__), "static")
settings["template_path"] = os.path.join(os.path.dirname(__file__), "templates")
settings["xsrf_cookies"] = False
