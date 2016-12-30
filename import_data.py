from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, User, Subject, Post

engine = create_engine('sqlite:///localtutors.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# po = session.query(Post).delete()
# print 'deleted %s rows from Post' % po
# session.commit()

# sub = session.query(Subject).delete()
# print 'deleted %s rows from Subject' % sub
# session.commit()

# us = session.query(User).delete()
# print 'deleted %s rows from User' % us
# session.commit()

sub1 = Subject(name='science')
sub2 = Subject(name="math")
sub3 = Subject(name='english')
sub4 = Subject(name='social_studies')

session.add(sub1)
session.add(sub2)
session.add(sub3)
session.add(sub4)

session.commit()

u1 = User(name='John Jackson',email='abc@gmail.com')
u2 = User(name='Jack Johnson',email='xyz@gmail.com')

session.add(u1)
session.add(u2)

session.commit()

p1 = Post(description='great stuff',rate=35,user=u1,subject=sub1)
p2 = Post(description='ok stuff',rate=25,user=u2,subject=sub1)

session.add(p1)
session.add(p2)

session.commit()

