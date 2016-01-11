import os
import tornado.web
import tornado
import json
from tornado.concurrent import run_on_executor
from concurrent.futures import ThreadPoolExecutor

from framework.interface.handlers.base import APIRequestHandler, UIRequestHandler
from framework.db import models
from framework.log import logger
from framework.static import StaticAnalyzer
from framework.interface.utils import ALLOWED_EXTENSIONS, allowed_file
from framework.interface.settings import BASE_DIR, LOGS_FOLDER, UPLOADS_DIR, TOOLS_DIR, OUTPUT_DIR

MAX_WORKERS = 8


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

    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    @tornado.gen.coroutine
    def get(self):
        apps = self.db.session.query(models.StaticAnalyzer).all() or []

        if self.request.arguments:
            app_name = self.get_argument('apk')
            if app_name.strip('.apk') in [str(i) for i in apps]:
                logger.warn('Already scanned!')
                self.render('report.html', app=app_name.strip('.apk'), status="Finished")
            else:
                logger.warn("Scan in progress...")
                info = yield self.extract_and_decompile(app_name)
                db_obj = models.StaticAnalyzer(app_name.strip('.apk'),
                                                info,
                                                "Running")
                self.db.session.add(db_obj)
                self.db.session.commit()
            self.redirect('/report?app='+app_name.strip('.apk')+'&status=Running')
        else:
            self.render('dashboard.html', apps=apps)

    @run_on_executor
    def extract_and_decompile(self, app_name):
        scan_obj = StaticAnalyzer(app_name)
        return json.dumps(scan_obj.init())


class ReportHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        app_name = self.get_argument('app')
        status = self.get_argument('status')
        self.render('report.html', app=app_name, status=status)


class AboutHandler(UIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    @tornado.web.asynchronous
    def get(self):
        self.render('about.html')


class ScanHandler(APIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    @tornado.gen.coroutine
    def get(self):
        apk = self.get_argument('app')
        data = self.db.session.query(models.StaticAnalyzer).filter_by(name=apk.strip('.apk')).first()
        out = yield self.scan(apk)
        data.info = json.dumps(out)
        self.db.session.commit()
        self.write(out)

    @run_on_executor
    def scan(self, apk):
        scan_obj = StaticAnalyzer(apk)
        return scan_obj.scan()


class StatusHandler(APIRequestHandler):
    SUPPORTED_METHODS = 'POST'

    def post(self):
        app = self.get_argument('app', None)
        status = self.get_argument('status', None)
        try:
            row = self.db.session.query(models.StaticAnalyzer).filter_by(name=app).first()
            row.status = status
            self.db.session.commit()
        except:
            logger.error("Cannot set status!")


class StaticAnalyzerData(APIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        app = self.request.arguments['app'][0]
        # get the data from DB
        data = self.db.session.query(models.StaticAnalyzer).filter_by(name=app).first()
        self.write(json.loads(fetch.info))


class DynamicAnalyzerData(APIRequestHandler):
    SUPPORTED_METHODS = ['GET']

    def get(self):
        pass
