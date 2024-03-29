from framework.interface.handlers import base, main


url_patterns = [
    (r"/", main.IndexHandler),
    (r"/about", main.AboutHandler),
    (r"/dashboard", main.DashboardHandler),
    (r"/report", main.ReportHandler),
    (r"/api/fetch", main.StaticAnalyzerData),
    (r"/api/scan", main.ScanHandler),
    (r"/api/status", main.StatusHandler)
]

