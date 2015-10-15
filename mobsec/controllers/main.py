import os
import base64
from flask import Blueprint, render_template, flash, request, redirect, url_for
from werkzeug import secure_filename
from mobsec.extensions import cache
from mobsec.settings import UPLOADS_DIR
from mobsec.utils import allowed_file


main = Blueprint('main', __name__)


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
                                    apk=base64.b64encode(app_name)))
        else:
            flash("Illegal extension!")
            return redirect(url_for(".home"))


@main.route("/dashboard", methods=['GET'])
def dashboard():
    return render_template('dashboard.html')


