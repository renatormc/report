from sqlalchemy.orm import class_mapper, ColumnProperty
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import models as mf
from database import Base as Base_from
from database import db_session as db_session_from
from sqlalchemy.sql.schema import Table
import settings


engine_to = create_engine(f"sqlite:///{settings.work_dir}/.report/db.db")
db_session_to = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine_to))

def get_list_classes(module):
    """Retorna a lista de models de um modulo"""
    list_ = []
    for item in dir(module):
        obj = getattr(module, item)
        if hasattr(obj, "__tablename__"):
            list_.append(item)
    return list_


def attribute_names(cls):
    """Retorna os atributos da classe que são do tipo Column"""
    return [prop.key for prop in class_mapper(cls).iterate_properties
        if isinstance(prop, ColumnProperty)]


def run_migrate():
    Base_from.metadata.create_all(bind=engine_to)

    for class_name in get_list_classes(mf):
        class_ = getattr(mf, class_name)
        props = attribute_names(class_)
        items = db_session_from.query(class_).all()
        for item in items:
            new_item = class_()
            for prop in props:
                setattr(new_item, prop, getattr(item, prop))
            db_session_to.add(new_item)
    db_session_to.commit()

    #Copiar dados das tabelas ponte
    conn_from = db_session_from.connection()
    conn_to = db_session_to.connection()
    for item in dir(mf):
        obj = getattr(mf, item)
        if obj.__class__ == Table:
            stm = obj.select()
            res = conn_from.execute(stm).fetchall()
            for item in res:
                cols = [c.name for c in obj.columns]
                stm = obj.insert().values(dict(zip(cols, item)))
                conn_to.execute(stm)
    db_session_to.commit()
