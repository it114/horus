import tornado.httpserver
import tornado.ioloop
from tornado import options
import tornado.web

from framework.interface.settings import settings
from framework.interface.urls import url_patterns
from framework.db.db import DB


class Application(tornado.web.Application):
    def __init__(self):
        tornado.web.Application.__init__(self, url_patterns, **settings)
        self.db = DB()

def main():
    app = Application()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(5000)
    tornado.ioloop.IOLoop.instance().start()
    app.db.create_session()

if __name__ == "__main__":
    main()
