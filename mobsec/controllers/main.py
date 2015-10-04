import os
from flask import Blueprint, render_template, flash, request, redirect, url_for
from werkzeug import secure_filename

from mobsec.extensions import cache


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
        apk = request.files['apk']
        if apk:
            app_name = secure_filename(apk)
            apk.save()
            return redirect(url_for("dashboard"))

@main.route("/dashboard", methods=['GET'])
def dashboard():
    return render_template('dashboard.html')
