from flask.ext.sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class StaticAnalyzerAndroid(db.Model):
    __tablename__ = "static_analyzer"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    name = db.Column(db.String())
    info = db.Column(db.String())

    def __init__(self, name, info):
        self.name = name
        self.info = info

    def __repr__(self):
        return self.name
