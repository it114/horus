import os
import json
import stat
import time
import hashlib
import datetime
import mimetypes
import email.utils
import tornado.web
import tornado.template
from urllib import quote_plus


class APIRequestHandler(tornado.web.RequestHandler):

    def write(self, chunk):
        if isinstance(chunk, list):
            super(APIRequestHandler, self).write(json.dumps(chunk))
            self.set_header("Content-Type", "application/json")
        else:
            super(APIRequestHandler, self).write(chunk)


class UIRequestHandler(tornado.web.RequestHandler):
    def reverse_url(self, name, *args):
        url = super(UIRequestHandler, self).reverse_url(name, *args)
        url = url.replace('?','')
        return url.split('None')[0]
