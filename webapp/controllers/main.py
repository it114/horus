import os
import json
from flask import Blueprint, render_template, flash, request, redirect, url_for, send_from_directory
from werkzeug import secure_filename
from webapp.extensions import cache
from webapp.settings import UPLOADS_DIR, OUTPUT_DIR
from webapp.utils import crossdomain, allowed_file
from framework.log import logger
from webapp.models import db, StaticAnalyzerAndroid
from framework.static import StaticAnalyzer

from flask_restful import Resource, Api


api = Api()

main = Blueprint('main', __name__)
api.init_app(main)


@main.route('/')
@cache.cached(timeout=1000)
def home():
    return render_template('index.html')


@main.route('/about')
@cache.cached(timeout=1000)
def about():
    return render_template('about.html')


@main.route("/", methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        apk = request.files['files[]']
        if apk and allowed_file(apk.filename):
            app_name = secure_filename(apk.filename)
            apk.save(os.path.join(UPLOADS_DIR, app_name))
            return redirect(url_for(".dashboard",
                                    apk=app_name))
        else:
            flash("Illegal extension!")
            logger.warn("Illegal extension.")
            return redirect(url_for(".home"))


@main.route("/dashboard")
def dashboard():
    # returns a list of analyzed apps
    apps = StaticAnalyzerAndroid.query.all() or []

    if request.args:
        app_name = str(request.args["apk"] or None).strip('.apk')
        if app_name in [str(i) for i in apps]:
            flash("Already scanned!")
            logger.warn('Already scanned app.')
            return redirect(url_for('.report', app_name=app_name, status='Done'))
        else:
            flash("Scan in progress...")
            # add the app to the DB
            scan_obj = StaticAnalyzer(request.args["apk"])
            #results = scan_obj.scan()
            new_app = StaticAnalyzerAndroid(app_name, json.dumps(scan_obj.info()), status="Running")
            db.session.add(new_app)
            db.session.commit()
            return redirect(url_for('.report', app_name=app_name, status='Running'))
    return render_template('dashboard.html', apps=apps)


@main.route("/dashboard/<app_name>/status=<status>", methods=['GET'])
def report(app_name, status):
    return render_template('report.html')


@main.route("/graph/<app>")
def graph(app):
    return render_template('graph.html')


@main.route("/cfg/<path:filename>")
@crossdomain(origin="*")
def fetch_gexf(filename):
    print "yay!"
    app = filename.split(".apk_final")[0]
    print app
    return send_from_directory(os.path.join(OUTPUT_DIR, app), filename)


class GetAllApps(Resource):
    def get(self):
        apps = [[str(i)] for i in StaticAnalyzerAndroid.query.all()]
        return apps


class SetStatus(Resource):
    def post(self, app, status):
        app_name = app
        try:
            row = StaticAnalyzerAndroid.query.filter_by(name=app_name).first()
            row.status = status
            db.session.commit()
            return True
        except:
            return False


class FetchDB(Resource):
    def get(self, app):
        app_name = app
        # fetch the data from the db
        fetch = StaticAnalyzerAndroid.query.filter_by(name=app_name).first()
        return json.loads(fetch.info)


class Scan(Resource):
    def get(self, app):
        app_name = app
        scan_obj = StaticAnalyzer(app_name)
        scan_obj.genCFG()
        return scan_obj.scan()


api.add_resource(GetAllApps, '/api/apps')
api.add_resource(Scan, '/api/scan/<app>')
api.add_resource(FetchDB, '/api/fetch/<app>')
api.add_resource(SetStatus, '/api/<status>')