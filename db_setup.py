import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    @property
    def serialize(self):
        return{
            'name': self.name,
            'id': self.id,
            'email': self.email
        }


class Subject(Base):
    __tablename__ = 'subject'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return{
            'id': self.id,
            'name': self.name
        }


class Post(Base):
    __tablename__ = 'post'

    id = Column(Integer, primary_key=True)
    title = Column(String(50), nullable=False)
    description = Column(String, nullable=False)
    rate = Column(Integer, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    subject_id = Column(Integer, ForeignKey('subject.id'))
    subject = relationship(Subject)

    @property
    def serialize(self):
        return{
            'id': self.id,
            'user': self.user.name,
            'title': self.title,
            'description': self.description,
            'rate': self.rate,
            'email': self.user.email
        }


engine = create_engine('sqlite:///localtutors.db')
Base.metadata.create_all(engine)
