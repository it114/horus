from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import create_engine, event, exc, schema
from sqlalchemy.engine import Engine

from framework.log import logger
from framework.db import models


metadata = schema.MetaData()


class DB(object):
    def __init__(self):
        self.create_session()

    def create_session(self):
        self.session = self.create_scoped_session()

    def clean_up(self):
        """Close the sqlalchemy session opened by DB."""
        self.session.close()

    def create_engine(self, BaseClass):
        try:
            engine = create_engine('sqlite:////tmp/horus.db')
            BaseClass.metadata.create_all(engine)
            return engine
        except ValueError as e:  # Potentially corrupted DB config.
            logger.error(e)
        except KeyError:  # Indicates incomplete db config file
            logger.error('Incomplete database configuration settings')
        except exc.OperationalError as e:
            logger.error('No such db!')

    def create_scoped_session(self):
        self.engine = self.create_engine(models.Base)
        session_factory = sessionmaker(bind=self.engine)
        return scoped_session(session_factory)
