import tornado.web
from webapp.handlers.base import APIRequestHandler,
                                 UIRequestHandler


class MainHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        self.render('index.html')
