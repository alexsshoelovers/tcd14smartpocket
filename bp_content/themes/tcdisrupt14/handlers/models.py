
from google.appengine.ext import ndb
# Put here your models or extend User model from bp_includes/models.py

class SmartPocketUser(ndb.Model):
	deviceId=ndb.StringProperty()
	facebookId=ndb.StringProperty()
	userId=ndb.StringProperty()
	created = ndb.DateTimeProperty(auto_now_add=True)
	updated = ndb.DateTimeProperty(auto_now=True)

class SmartPocketUserCard(ndb.Model):
	userId=ndb.StringProperty()
	mastercardId=ndb.StringProperty()
	customerId=ndb.StringProperty()
	info = ndb.TextProperty()	
	cardType=ndb.StringProperty()
	cardId=ndb.StringProperty()
	cardName=ndb.StringProperty()
	cardEnding=ndb.StringProperty()
	email=ndb.StringProperty()
	created = ndb.DateTimeProperty(auto_now_add=True)
	updated = ndb.DateTimeProperty(auto_now=True)

class SampleProduct(ndb.Model):
	code=ndb.StringProperty()
	name=ndb.StringProperty()
	image=ndb.StringProperty()
	price=ndb.StringProperty()
	category=ndb.StringProperty()
	brand=ndb.StringProperty()

class Cart(ndb.Model):
	name=ndb.StringProperty()
	image=ndb.StringProperty()
	price=ndb.StringProperty()