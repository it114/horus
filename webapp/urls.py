from webapp.handlers import base, main


url_patterns = [
    (r"/", base.MainHandler),
]
