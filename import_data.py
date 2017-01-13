from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, User, Subject, Post

engine = create_engine('sqlite:///localtutors.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Uncomment the following lines to delete everything in the database

po = session.query(Post).delete()
print 'deleted %s rows from Post' % po
session.commit()

sub = session.query(Subject).delete()
print 'deleted %s rows from Subject' % sub
session.commit()

us = session.query(User).delete()
print 'deleted %s rows from User' % us
session.commit()

# Creates generic users in database
u1 = User(name='John Jackson', email='abc@gmail.com',
          picture='/static/pictures/resA.png')
u2 = User(name='Jack Johnson', email='xyz@gmail.com',
          picture='/static/pictures/resA.png')

session.add(u1)
session.add(u2)

session.commit()

# Creates subjects in database
sub1 = Subject(name='science', user=u1)
sub2 = Subject(name="math", user=u1)
sub3 = Subject(name='english', user=u2)
sub4 = Subject(name='social_studies', user=u2)

session.add(sub1)
session.add(sub2)
session.add(sub3)
session.add(sub4)

session.commit()

# Creates example posts for database
d1 = '''
Concipio ad lectorum illamque saeculum supponit ut si.
Veritates se recurrunt existenti ex potestate cerebella.
Nulla ne summa ut eo vitam. Dum via negat cau ferri certe.
Ha dignemini adjuvetis clausulas profundum eo. Innotuit
gurgitem vis sequitur imo conversa.
'''

d2 = '''
Actualis at conscius supponam ac. Vocem si longo mo co veris entis.
Similibus essentiae argumenti sum contingit eae praesenti.
Spectatum de jactantur veritatis ut. Negans impetu optima nos
postea rectum primas una. Actu iste ego lor haec ipsa quia tria meo.
Eam unquam vim obstat eamque nia factam manebo. Anima terea ideas tur
putem nec nolim aliae imo.
'''

p1 = Post(title='Physics', description=d1,
          rate=35, user=u1, subject=sub1)
p2 = Post(title='Biology', description=d2,
          rate=25, user=u2, subject=sub1)

session.add(p1)
session.add(p2)

session.commit()
