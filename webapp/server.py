import tornado.httpserver
import tornado.ioloop
from tornado import options
import tornado.web
import tornado.autoreload
import tornado.web

from webapp.settings import settings
from webapp.urls import url_patterns


class ApplicationServer(tornado.web.Application):
    def __init__(self):
        tornado.web.Application.__init__(self, url_patterns, **settings)


def main():
    app = ApplicationServer()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
