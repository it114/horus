from flask import Blueprint, render_template, flash, request, redirect, url_for
from mobsec.extensions import cache


main = Blueprint('main', __name__)

@main.route('/')
@cache.cached(timeout=1000)
def home():
    return render_template('index.html')

