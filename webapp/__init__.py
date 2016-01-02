#! ../env/bin/python
# -*- coding: utf-8 -*-

__version__ = '0.11'

from flask import Flask
from webassets.loaders import PythonLoader as PythonAssetsLoader
from webapp.controllers.main import main
from webapp import assets
from webapp.models import db

from webapp.extensions import (
    cache,
    assets_env,
    debug_toolbar,
)


def create_app(object_name, env="dev"):
    """
    An flask application factory, as explained here:
    http://flask.pocoo.org/docs/patterns/appfactories/

    """

    app = Flask(__name__)

    app.config.from_object(object_name)
    app.config['ENV'] = env
    # initialize the cache
    cache.init_app(app)

    # initialize the debug tool bar
    debug_toolbar.init_app(app)

    # initialize SQLAlchemy
    db.init_app(app)

    # Import and register the different asset bundles
    assets_env.init_app(app)
    assets_loader = PythonAssetsLoader(assets)
    for name, bundle in assets_loader.load_bundles().items():
        assets_env.register(name, bundle)

    # register our blueprints
    app.register_blueprint(main)

    return app
