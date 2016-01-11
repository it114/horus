import os
import tornado.web
import json

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
                self.redirect('/dashboard?apk='+filename)
            else:
                logger.error("Invalid file!")
                self.render('index.html')
        except:
            logger.error("Cannot upload!")


class DashboardHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        apps = self.db.session.query(models.StaticAnalyzer).all() or []

        if self.request.arguments:
            app_name = str(self.request.arguments["apk"][0] or None).strip('.apk')
            if app_name in [str(i) for i in apps]:
                logger.warn('Already scanned!')
                self.render('report.html', app=app_name, status="Finished")
            else:
                logger.warn("Scan in progress...")
                db_obj = models.StaticAnalyzer(app_name, json.dumps({}), "Running")
                self.db.session.add(db_obj)
                self.db.session.commit()
            self.redirect('/report?app='+app_name+'&status=Running')
        else:
            self.render('dashboard.html', apps=apps)


class ReportHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        app_name = self.request.arguments['app'][0]
        status = self.request.arguments['status'][0]
        self.render('report.html', app=app_name, status=status)


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
