from flask_assets import Bundle

common_css = Bundle(
    'css/vendor/bootstrap.min.css',
    'css/vendor/helper.css',
    'css/span-fix.css',
    'css/main.css',
    'css/spinner.css',
    'css/vendor/font-awesome.min.css',
    'css/admin.css',
    'css/skin-blue.css',
    filters='cssmin',
    output='public/css/common.css'
)

common_js = Bundle(
    'js/vendor/jquery.min.js',
    'js/vendor/bootstrap.min.js',
    'js/app.min.js',
    Bundle(
        'js/main.js',
        filters='jsmin'
    ),
    output='public/js/common.js'
)
