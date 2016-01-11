from webapp.handlers import base, main


url_patterns = [
    (r"/", main.IndexHandler),
    (r"/about", main.AboutHandler),
    (r"/dashboard", main.DashboardHandler),
]
