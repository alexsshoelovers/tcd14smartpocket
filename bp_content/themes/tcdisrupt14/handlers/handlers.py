# -*- coding: utf-8 -*-

"""
    A real simple app for using webapp2 with auth and session.

    It just covers the basics. Creating a user, login, logout
    and a decorator for protecting certain handlers.

    Routes are setup in routes.py and added in main.py
"""
# standard library imports
import re
import logging
# related third party imports
import webapp2
import json 
import random
from google.appengine.ext import ndb
from google.appengine.api import taskqueue
from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError
from webapp2_extras.i18n import gettext as _
from bp_includes.external import httpagentparser
# local application/library specific imports
import bp_includes.lib.i18n as i18n
from bp_includes.lib.basehandler import BaseHandler
from bp_includes.lib.decorators import user_required
from bp_includes.lib import captcha, utils
import bp_includes.models as models_boilerplate
import forms as forms
import simplify
import models
class ContactHandler(BaseHandler):
    """
    Handler for Contact Form
    """

    def get(self):
        """ Returns a simple HTML for contact form """

        if self.user:
            user_info = self.user_model.get_by_id(long(self.user_id))
            if user_info.name or user_info.last_name:
                self.form.name.data = user_info.name + " " + user_info.last_name
            if user_info.email:
                self.form.email.data = user_info.email
        params = {
            "exception": self.request.get('exception')
        }

        return self.render_template('contact.html', **params)

    def post(self):
        """ validate contact form """
        if not self.form.validate():
            return self.get()

        remote_ip = self.request.remote_addr
        city = i18n.get_city_code(self.request)
        region = i18n.get_region_code(self.request)
        country = i18n.get_country_code(self.request)
        coordinates = i18n.get_city_lat_long(self.request)
        user_agent = self.request.user_agent
        exception = self.request.POST.get('exception')
        name = self.form.name.data.strip()
        email = self.form.email.data.lower()
        message = self.form.message.data.strip()
        template_val = {}

        challenge = self.request.POST.get('recaptcha_challenge_field')
        response = self.request.POST.get('recaptcha_response_field')
        cResponse = captcha.submit(
            challenge,
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if re.search(r"(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})", message) and not cResponse.is_valid:
            chtml = captcha.displayhtml(
            public_key=self.app.config.get('captcha_public_key'),
            use_ssl=(self.request.scheme == 'https'),
            error=None)
            if self.app.config.get('captcha_public_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE" or \
                            self.app.config.get('captcha_private_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE":
                chtml = '<div class="alert alert-danger"><strong>Error</strong>: You have to ' \
                        '<a href="http://www.google.com/recaptcha/whyrecaptcha" target="_blank">sign up ' \
                        'for API keys</a> in order to use reCAPTCHA.</div>' \
                        '<input type="hidden" name="recaptcha_challenge_field" value="manual_challenge" />' \
                        '<input type="hidden" name="recaptcha_response_field" value="manual_challenge" />'
            template_val = {
                "captchahtml": chtml,
                "exception": exception,
                "message": message,
                "name": name,

            }
            if not cResponse.is_valid and response is None:
                _message = _("Please insert the Captcha in order to finish the process of sending the message")
                self.add_message(_message, 'warning')
            elif not cResponse.is_valid:
                _message = _('Wrong image verification code. Please try again.')
                self.add_message(_message, 'danger')


            return self.render_template('contact.html', **template_val)
        else:
            try:
                # parsing user_agent and getting which os key to use
                # windows uses 'os' while other os use 'flavor'
                ua = httpagentparser.detect(user_agent)
                _os = ua.has_key('flavor') and 'flavor' or 'os'

                operating_system = str(ua[_os]['name']) if "name" in ua[_os] else "-"
                if 'version' in ua[_os]:
                    operating_system += ' ' + str(ua[_os]['version'])
                if 'dist' in ua:
                    operating_system += ' ' + str(ua['dist'])

                browser = str(ua['browser']['name']) if 'browser' in ua else "-"
                browser_version = str(ua['browser']['version']) if 'browser' in ua else "-"

                template_val = {
                    "name": name,
                    "email": email,
                    "ip": remote_ip,
                    "city": city,
                    "region": region,
                    "country": country,
                    "coordinates": coordinates,

                    "browser": browser,
                    "browser_version": browser_version,
                    "operating_system": operating_system,
                    "message": message
                }
            except Exception as e:
                logging.error("error getting user agent info: %s" % e)

            try:
                subject = _("Contact") + " " + self.app.config.get('app_name')
                # exceptions for error pages that redirect to contact
                if exception != "":
                    subject = "{} (Exception error: {})".format(subject, exception)

                body_path = "emails/contact.txt"
                body = self.jinja2.render_template(body_path, **template_val)

                email_url = self.uri_for('taskqueue-send-email')
                taskqueue.add(url=email_url, params={
                    'to': self.app.config.get('contact_recipient'),
                    'subject': subject,
                    'body': body,
                    'sender': self.app.config.get('contact_sender'),
                })

                message = _('Your message was sent successfully.')
                self.add_message(message, 'success')
                return self.redirect_to('contact')

            except (AttributeError, KeyError), e:
                logging.error('Error sending contact form: %s' % e)
                message = _('Error sending the message. Please try again later.')
                self.add_message(message, 'danger')
                return self.redirect_to('contact')

    @webapp2.cached_property
    def form(self):
        return forms.ContactForm(self)


class SecureRequestHandler(BaseHandler):
    """
    Only accessible to users that are logged in
    """

    @user_required
    def get(self, **kwargs):
        user_session = self.user
        user_session_object = self.auth.store.get_session(self.request)

        user_info = self.user_model.get_by_id(long(self.user_id))
        user_info_object = self.auth.store.user_model.get_by_auth_token(
            user_session['user_id'], user_session['token'])

        try:
            params = {
                "user_session": user_session,
                "user_session_object": user_session_object,
                "user_info": user_info,
                "user_info_object": user_info_object,
                "userinfo_logout-url": self.auth_config['logout_url'],
            }
            return self.render_template('secure_zone.html', **params)
        except (AttributeError, KeyError), e:
            return "Secure zone error:" + " %s." % e


class DeleteAccountHandler(BaseHandler):

    @user_required
    def get(self, **kwargs):
        chtml = captcha.displayhtml(
            public_key=self.app.config.get('captcha_public_key'),
            use_ssl=(self.request.scheme == 'https'),
            error=None)
        if self.app.config.get('captcha_public_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE" or \
                        self.app.config.get('captcha_private_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE":
            chtml = '<div class="alert alert-danger"><strong>Error</strong>: You have to ' \
                    '<a href="http://www.google.com/recaptcha/whyrecaptcha" target="_blank">sign up ' \
                    'for API keys</a> in order to use reCAPTCHA.</div>' \
                    '<input type="hidden" name="recaptcha_challenge_field" value="manual_challenge" />' \
                    '<input type="hidden" name="recaptcha_response_field" value="manual_challenge" />'
        params = {
            'captchahtml': chtml,
        }
        return self.render_template('delete_account.html', **params)

    def post(self, **kwargs):
        challenge = self.request.POST.get('recaptcha_challenge_field')
        response = self.request.POST.get('recaptcha_response_field')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            challenge,
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _('Wrong image verification code. Please try again.')
            self.add_message(_message, 'danger')
            return self.redirect_to('delete-account')

        if not self.form.validate() and False:
            return self.get()
        password = self.form.password.data.strip()

        try:

            user_info = self.user_model.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username
            password = utils.hashing(password, self.app.config.get('salt'))

            try:
                # authenticate user by its password
                user = self.user_model.get_by_auth_password(auth_id, password)
                if user:
                    # Delete Social Login
                    for social in models_boilerplate.SocialUser.get_by_user(user_info.key):
                        social.key.delete()

                    user_info.key.delete()

                    ndb.Key("Unique", "User.username:%s" % user.username).delete_async()
                    ndb.Key("Unique", "User.auth_id:own:%s" % user.username).delete_async()
                    ndb.Key("Unique", "User.email:%s" % user.email).delete_async()

                    #TODO: Delete UserToken objects

                    self.auth.unset_session()

                    # display successful message
                    msg = _("The account has been successfully deleted.")
                    self.add_message(msg, 'success')
                    return self.redirect_to('home')


            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _("Incorrect password! Please enter your current password to change your account settings.")
                self.add_message(message, 'danger')
            return self.redirect_to('delete-account')

        except (AttributeError, TypeError), e:
            login_error_message = _('Your session has expired.')
            self.add_message(login_error_message, 'danger')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.DeleteAccountForm(self)


class PaymentformHandler(BaseHandler):
    """
    Handler for Contact Form
    """

    def get(self):
        params ={}
        return self.render_template('paymentform.html')

    def post(self):
        params ={}
        simplify.public_key = "sbpb_MzUxMDVmMDEtZTI5Ni00YjI2LTkyMTAtODhjZGYyMzA3ZWNl"
        simplify.private_key = "aLnp4PbmCnsi67GeSAq8ipEtR/SkBzhgCCJ4OgWiduh5YFFQL0ODSXAOkNtXTToq"
        token_id =self.request.get('simplifyToken') 
        payment = simplify.Payment.create({
                "amount" : "1000",
                "token" : token_id,
                "description" : "payment description",
                "reference" : "7a6ef6be31",
                "currency" : "USD"
         
        })
         
        if payment.paymentStatus == 'APPROVED':
            self.response.out.write("Payment approved")
        else:
            self.response.out.write("Payment rejected")

class AddCardHandler(BaseHandler):
    def get(self):
        params={}
        return self.render_template('createCardUser.html', **params)


    def post(self):
        items = self.request.POST.items()
        email = self.request.get('email')
        ownername= self.request.get('ownername')
        #self.response.out.write(json.dumps(items))
        token_id =self.request.get('simplifyToken')   

        simplify.public_key = "sbpb_MzUxMDVmMDEtZTI5Ni00YjI2LTkyMTAtODhjZGYyMzA3ZWNl"
        simplify.private_key = "aLnp4PbmCnsi67GeSAq8ipEtR/SkBzhgCCJ4OgWiduh5YFFQL0ODSXAOkNtXTToq"

        customer = simplify.Customer.create({
        "token" : token_id,
        "email" : email,
        "name" : ownername,
        "reference" : "Ref1"
 
})
        self.response.out.write('%s' % str(customer))
        #actually we need to remove the customer piece of info (too much for us to store)
        logging.info('CUSTOMER DATA: %s' % customer)
        try:
            dbuser = models.SmartPocketUserCard(customerId=customer.card.customer.id, mastercardId=customer.id, info=str(customer), cardEnding=customer.card.last4, cardId=customer.card.id, cardType=customer.card.type, cardName=customer.card.name, email=email)
            dbuser.put()
        except:
            self.response.out.write('Error adding card')
            return self.redirect_to('list_cards')
        return self.redirect_to('list_cards')

class ListCardsHandler(BaseHandler):
    def get(self):
        params ={}
        format=self.request.get('format','html')
        cards=models.SmartPocketUserCard.query()
        params['cards']=cards
        if format=='json':
            self.response.headers['Content-Type'] = 'application/json'
            resjson=[]
            for card in cards:
                resjson.append({"userId":card.userId,"mastercardId":card.mastercardId,"customerId":card.customerId, "cardType":card.cardType, "cardId":card.cardId,  "cardName":card.cardName,  "cardEnding":card.cardEnding,"imageUrl":"http://www.mastercard.com/global/_assets/img/products/standard-cc-intro.png"})

            resfinal = json.dumps(resjson)
            self.response.out.write( resfinal)
        else:
            return self.render_template('cardsList.html', **params)
        
class PaymentHandler(BaseHandler):
    def get(self):
        params={}
        cardid=self.request.get('cardId')
        card=models.SmartPocketUserCard.query(models.SmartPocketUserCard.cardId==cardid).fetch()
        logging.info('CARDID: %s' % cardid)
        logging.info('CARD: %s' % card)
        params['cardid']=cardid
        params['cards']=card
        return self.render_template('paymentform.html',**params)

    def post(self):
        amount=self.request.get('amount')
        cardId=self.request.get('cardId')
        userId=self.request.get('customerId')
        logging.info("AMOUNT: %s" % amount)
        logging.info("CUSTOMERID: %s" % userId)
        simplify.public_key = "sbpb_MzUxMDVmMDEtZTI5Ni00YjI2LTkyMTAtODhjZGYyMzA3ZWNl"
        simplify.private_key = "aLnp4PbmCnsi67GeSAq8ipEtR/SkBzhgCCJ4OgWiduh5YFFQL0ODSXAOkNtXTToq"
         
        payment = simplify.Payment.create({
                "amount" : amount,
                "customer" : userId,
                "description" : "SmartPocket",
                "reference" : "7a6ef6be31",
                "currency" : "USD"
         
        })
        
        if payment.paymentStatus == 'APPROVED':
            logging.info( "Payment approved")
        else:
            logging.info( "Payment not approved")
            logging.info(payment)

class LoadDatabaseHandler(BaseHandler):
    def get(self):
        price=set([
                50.3,
                25.6,
                42.8,
                33.0,
                8.99,
                25.5,
                60.0,
                15.5,
                20.99,
                40.5
            ])
        description = set([
                "Addict Ultra Gloss #256 Negligee Pink Christian Lip Color Addict Ultra Gloss",
                "Ombre Duo Lumiere No. 27 Golden Pink Precious Bronze",
                "Ombre Absolue Palette Radiant Smoothing Eye Shadow Quad # A40 Chant De Lavandes 4x",
                "L' Absolu Rouge Spf 12 No. 173 Rouge Preciosa",
                "Teint Renergie Lift R.a.r.e. Foundation Spf 20 # 06 Beige Cannelle Complexion Teint Renergie Lift R.a.r.e. Foundation Spf 20",
                "Pure Lip Gloss No. 06 Pure Plum Ysl Lip Color Pure Lip Gloss",
                "Men Grip Tight Firm Hold Gel",
                "96709 Le Lipstique Lip Colouring Stick With Brush No. Alpine Glow For Women Lip Color Unboxed Us Version",
                "show Extase Flash Plumping Mascara # 090 Black Extase",
                "Luminous Silk Foundation # 5 Warm Beige",
                "Le Crayon Khol Le Bleu De Jim Unboxed Us Version"
            ])
        code = set([
                    "0010369680102",
                    "0010409281702",
                    "0010457880902",
                    "0010481780902",
                    "0010491680902",
                    "0009131481702",
                    "0009271464344",
                    "0009670980902",
                    "0010139380102",
                    "0010685231002",
            ])
        category='Beauty - Personal Care - Hygiene'
        brand=set([
                "Revlon",
                "Helen of Troy L.P.",
                "Pacific World Corp",
                "Colomer",
                "Amsoil"
            ])
        image=set([
                "https://encrypted-tbn2.gstatic.com/shopping?q=tbn:ANd9GcTUIn5q_55D-0C4Ees1x-_Ob-3GiNzbuhHguPN4WiYjIaOFibQJJUbo-48MBS2T5a-_x3a-lGce&usqp=CAk",
                "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcSSERj9nCsY6ZkOdvrLCtzdql9L4_xqqL3otNyA1vszUVt1y5coVPhqvxv3aPecpCauOrPbVGpc&usqp=CAk",
                "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcSNl-FxupU76d8MNsPZVOemHG4KBriYx3x62f0DY-cbOICUpc05O9vv5lZPhM7Yf6MpdDqi6_x0&usqp=CAk",
                "https://encrypted-tbn1.gstatic.com/shopping?q=tbn:ANd9GcS-8cH-K-yCDdGJ7Aj4VEtUHKWvu-KCuFctUs4ZU0mpqtmasK9rsh67cIGVZzwUcXctCnCSoNjX&usqp=CAk",
                "https://encrypted-tbn2.gstatic.com/shopping?q=tbn:ANd9GcSxF3llTUztRQNrh36jaSaizFLWTqkIgmzwzV7buVgH469x6qMRl8HruQPkfmZGvzBS2mpgKke8&usqp=CAk",
                "https://encrypted-tbn2.gstatic.com/shopping?q=tbn:ANd9GcSjIxC_kSCN3SqC2dpaHeJfO3LBhnzmam_xLEY0Y3oWLneyClcA&usqp=CAk",
                "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcTkJk7prgl33r8XOAcfCExMg0uDbY34jLRxrmXVNLzy465XLPD-&usqp=CAk",
                "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcRpY3lnllm4zQG6jH6dKl0-1QKV58XwhpGg47CYxAPU8dJw0_CpFWAK4PXGvkwTdhSBCCsJ0QRPrg&usqp=CAk",
                "https://encrypted-tbn1.gstatic.com/shopping?q=tbn:ANd9GcSHY9E7ZnkSeXx2kfwgdLLobfKoHI5inPfhyjKpjrKcniim3c_p&usqp=CAk",
                "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcSwN3SqkJ3G9UpMgEIOJUNeGoNksXuGn_r-ZCx9oCTy4pfw2TddNun-dVBF0kOgipvxzcvzbEgh&usqp=CAk"
            ])
        r_code=random.sample(code,1)[0]
        r_name=random.sample(description,1)[0]
        r_image=random.sample(image,1)[0]
        r_price=str(random.sample(price
            ,1)[0])
        r_category=category
        r_brand=random.sample(brand,1)[0]
        product=models.SampleProduct(code=r_code, name=r_name, image=r_image, price=r_price, category=r_category, brand=r_brand)
        product.put()
        self.response.out.write(json.dumps(product.to_dict()))

class SampleHandler(BaseHandler):
    def get(self):
        params={}
        self.render_template('sample.html',**params)

class AddProductHandler(BaseHandler):
    def get(self):
        params={}
        name=self.request.get('name')
        image=self.request.get('image')
        price=self.request.get('price')
        addtocart=models.Cart(name=name, image=image, price=price)
        addtocart.put()

class GetCartHandler(BaseHandler):
    def get(self):
        params={}
        cartproducts=models.Cart.query().fetch()
        self.response.headers['Content-Type'] = 'application/json'
        resjson=[]
        for prod in cartproducts:
            resjson.append({"name":prod.name,"image":prod.image,"price":prod.price})

        resfinal = json.dumps(resjson)
        self.response.out.write(resfinal)


