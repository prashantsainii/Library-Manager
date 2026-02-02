from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database connection URL (SQLite file)
SQLALCHEMY_DATABASE_URL = 'sqlite:///./todosapp.db'     # db is inside this directory of todosapp


#engine is used to open up a connection, manages connections and for executing SQL statements.
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={'check_same_thread': False})  # check_same_thread=False allows the database to be accessed by multiple threads,

# SessionLocal is a factory for creating new database sessions.
# Each session represents a single unit of work (transaction) with the database.
# autocommit=False means changes must be committed explicitly.
# autoflush=False means changes are not sent to the database automatically.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base is the base class for all SQLAlchemy ORM models.
# All database table models will inherit from this Base class.
# SQLAlchemy uses this to collect metadata and create tables.
# to create the object of our database.py file
Base = declarative_base()