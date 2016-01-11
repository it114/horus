import tornado.web
from framework.interface.handlers.base import APIRequestHandler, UIRequestHandler

from framework.static import StaticAnalyzer



class IndexHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST']

    def get(self):
        self.render('index.html')

    def post(self):
        pass


class DashboardHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        pass


class ReportHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST']

    def get(self):
        pass

    def post(self):
        pass


class AboutHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        self.render('about.html')


class StaticAnalyzerData(APIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        pass


class DynamicAnalyzerData(APIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        pass


class ScanHandler(APIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        pass
