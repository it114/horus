from flask.ext.sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class StaticAnalyzerAndroid(db.Model):
    __tablename__ = "static_analyzer"

    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    name = db.Column(db.String())
    size = db.Column(db.Integer())
    md5 = db.Column(db.String())
    sha1 = db.Column(db.String())
    sha256 = db.Column(db.String())

    def __init__(self, name, size, md5, sha1, sha256):
        self.name = name
        self.size = size
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256

    def __repr__(self):
        return self.title
