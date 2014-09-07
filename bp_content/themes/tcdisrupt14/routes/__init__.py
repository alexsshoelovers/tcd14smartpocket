"""
Using redirect route instead of simple routes since it supports strict_slash
Simple route: http://webapp-improved.appspot.com/guide/routing.html#simple-routes
RedirectRoute: http://webapp-improved.appspot.com/api/webapp2_extras/routes.html#webapp2_extras.routes.RedirectRoute
"""
from webapp2_extras.routes import RedirectRoute
from bp_content.themes.tcdisrupt14.handlers import handlers

secure_scheme = 'https'

# Here go your routes, you can overwrite boilerplate routes (bp_includes/routes)

_routes = [
    RedirectRoute('/secure/', handlers.SecureRequestHandler, name='secure', strict_slash=True),
    RedirectRoute('/settings/delete_account', handlers.DeleteAccountHandler, name='delete-account', strict_slash=True),
    RedirectRoute('/contact/', handlers.ContactHandler, name='contact', strict_slash=True),
    RedirectRoute('/', handlers.ContactHandler, name='contact', strict_slash=True),
    RedirectRoute('/paymentform/', handlers.PaymentformHandler, name='paymentform', strict_slash=True),
    RedirectRoute('/add_card/', handlers.AddCardHandler, name='add_card', strict_slash=True),
    RedirectRoute('/list_cards/', handlers.ListCardsHandler, name='list_cards', strict_slash=True),
    RedirectRoute('/pay/', handlers.PaymentHandler, name='pay_with_card', strict_slash=True),
    RedirectRoute('/load_database/', handlers.LoadDatabaseHandler, name='load_database', strict_slash=True),
    RedirectRoute('/sample/', handlers.SampleHandler, name='sample_handler', strict_slash=True),
    RedirectRoute('/addProduct/', handlers.AddProductHandler, name='addProduct', strict_slash=True),
    RedirectRoute('/getCart/', handlers.GetCartHandler, name='getCart', strict_slash=True),
]

def get_routes():
    return _routes

def add_routes(app):
    if app.debug:
        secure_scheme = 'http'
    for r in _routes:
        app.router.add(r)
