from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import Table, Column, Integer, String, Boolean,\
    Float, DateTime, ForeignKey, Text, Index
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import relationship
import datetime


Base = declarative_base()


class StaticAnalyzerAndroid(Base):
    __tablename__ = "static_analyzer"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True)
    info = Column(String, unique=True)
    status = Column(String)

    def __repr__(self):
        return self.name
