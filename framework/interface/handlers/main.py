import os
import tornado.web
from framework.interface.handlers.base import APIRequestHandler, UIRequestHandler
from framework.db import models
from framework.log import logger
from framework.static import StaticAnalyzer
from framework.interface.utils import ALLOWED_EXTENSIONS, allowed_file
from framework.interface.settings import BASE_DIR, LOGS_FOLDER, UPLOADS_DIR, TOOLS_DIR, OUTPUT_DIR


class IndexHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST']

    @tornado.web.asynchronous
    def get(self):
        self.render('index.html')

    def post(self):
        try:
            apk = self.request.files['files[]']
            filename = apk[0]['filename']
            if apk and allowed_file(filename):
                # save the file in the uploads folder
                with open(os.path.join(UPLOADS_DIR, filename), "w") as out:
                    out.write(apk[0]['body'])
                logger.info("APK uploaded!")
            else:
                logger.error("Invalid file!")
        except:
            logger.error("Cannot upload!")


class DashboardHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    @tornado.web.asynchronous
    def get(self):
        all_apps = self.db.session.query(models.StaticAnalyzer).all() or []
        self.render('dashboard.html', apps=all_apps)


class ReportHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST']

    def get(self):
        pass

    def post(self):
        pass


class AboutHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    @tornado.web.asynchronous
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
