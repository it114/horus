import os
from flask import Blueprint, render_template, flash, request, redirect, url_for
from werkzeug import secure_filename
from mobsec.extensions import cache
from mobsec.settings import UPLOADS_DIR
from mobsec.utils import allowed_file
from mobsec.log import logger
from mobsec.models import StaticAnalyzerAndroid
from mobsec.controllers.static_analyzer import StaticAnalyzer

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
    app_name = str(request.args["apk"] or None).strip('.apk')

    # returns a list of analyzed apps
    apps = StaticAnalyzerAndroid.query.all()
    if app_name in [str(i) for i in apps]:
        flash("Already scanned!")
        logger.warn('Already scanned app.')
    else:
        flash("Scan in progress...")
    return render_template('dashboard.html')


class ScanAPI(Resource):
    """
    + starts scan
    """
    def get(self):
        pass

    def post(self):
        app_name = request.form['apk']
        scan_obj = StaticAnalyzer(app_name)

        return {'scan': scan_obj.size()}

api.add_resource(ScanAPI, '/api/scan')
