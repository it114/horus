from flask_assets import Bundle

common_css = Bundle(
    'css/vendor/bootstrap.min.css',
    'css/vendor/bootstrap-theme.min.css',
    'css/vendor/helper.css',
    'css/span-fix.css',
    'css/main.css',
    'css/dashboard.css',
    'css/spinner.css',
    'css/vendor/font-awesome.min.css',
    filters='cssmin',
    output='public/css/common.css'
)

common_js = Bundle(
    'js/vendor/jquery.min.js',
    'js/vendor/jquery-ui.min.js',
    'js/vendor/jquery.mousewheel.min.js',
    'js/vendor/bootstrap.min.js',
    'js/sigma.min.js',
    'js/sigma.parsers.json.min.js',
    Bundle(
        'js/main.js',
        filters='jsmin'
    ),
    output='public/js/common.js'
)
