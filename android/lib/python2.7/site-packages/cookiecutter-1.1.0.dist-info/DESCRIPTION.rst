=============
Cookiecutter
=============

.. image:: https://img.shields.io/pypi/v/cookiecutter.svg
        :target: https://pypi.python.org/pypi/cookiecutter/1.0.0

.. image:: https://travis-ci.org/audreyr/cookiecutter.png?branch=master
        :target: https://travis-ci.org/audreyr/cookiecutter

.. image:: https://ci.appveyor.com/api/projects/status/github/audreyr/cookiecutter?branch=master
        :target: https://ci.appveyor.com/project/audreyr/cookiecutter/branch/master

.. image:: https://img.shields.io/pypi/dm/cookiecutter.svg
        :target: https://pypi.python.org/pypi/cookiecutter/1.0.0

.. image:: https://codecov.io/github/audreyr/cookiecutter/coverage.svg?branch=master
        :target: https://codecov.io/github/audreyr/cookiecutter?branch=master

.. image:: https://badges.gitter.im/Join Chat.svg
        :target: https://gitter.im/audreyr/cookiecutter?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

.. image:: https://readthedocs.org/projects/cookiecutter/badge/?version=latest
        :target: https://readthedocs.org/projects/cookiecutter/?badge=latest
        :alt: Documentation Status

.. image:: https://landscape.io/github/audreyr/cookiecutter/master/landscape.svg?style=flat
        :target: https://landscape.io/github/audreyr/cookiecutter/master
        :alt: Code Health

A command-line utility that creates projects from **cookiecutters** (project
templates), e.g. creating a Python package project from a Python package project template.

* Documentation: http://cookiecutter.rtfd.org
* GitHub: https://github.com/audreyr/cookiecutter
* Free software: BSD license
* PyPI: https://pypi.python.org/pypi/cookiecutter

.. image:: https://raw.github.com/audreyr/cookiecutter/aa309b73bdc974788ba265d843a65bb94c2e608e/cookiecutter_medium.png

Features
--------

Did someone say features?

* Cross-platform: Windows, Mac, and Linux are officially supported.

* Works with Python 2.7, 3.3, 3.4, 3.5, and PyPy. *(But you don't have to know/write Python
  code to use Cookiecutter.)*

* Project templates can be in any programming language or markup format:
  Python, JavaScript, Ruby, CoffeeScript, RST, Markdown, CSS, HTML, you name
  it. You can use multiple languages in the same project template.

* Simple command line usage:

    .. code-block:: bash

        # Create project from the cookiecutter-pypackage.git repo template
        # You'll be prompted to enter values.
        # Then it'll create your Python package in the current working directory,
        # based on those values.
        $ cookiecutter https://github.com/audreyr/cookiecutter-pypackage
        # For the sake of brevity, repos on GitHub can just use the 'gh' prefix
        $ cookiecutter gh:audreyr/cookiecutter-pypackage

* Can also use it at the command line with a local template:

    .. code-block:: bash

        # Create project in the current working directory, from the local
        # cookiecutter-pypackage/ template
        $ cookiecutter cookiecutter-pypackage/

* Or use it from Python:

    .. code-block:: python

        from cookiecutter.main import cookiecutter

        # Create project from the cookiecutter-pypackage/ template
        cookiecutter('cookiecutter-pypackage/')

        # Create project from the cookiecutter-pypackage.git repo template
        cookiecutter('https://github.com/audreyr/cookiecutter-pypackage.git')

* Directory names and filenames can be templated. For example::

    {{cookiecutter.repo_name}}/{{cookiecutter.repo_name}}/{{cookiecutter.repo_name}}.py

* Supports unlimited levels of directory nesting.

* 100% of templating is done with Jinja2. This includes file and directory names.

* Simply define your template variables in a `cookiecutter.json` file. For example:

    .. code-block:: json

        {
            "full_name": "Audrey Roy",
            "email": "audreyr@gmail.com",
            "project_name": "Complexity",
            "repo_name": "complexity",
            "project_short_description": "Refreshingly simple static site generator.",
            "release_date": "2013-07-10",
            "year": "2013",
            "version": "0.1.1"
        }

* Unless you suppress it with `--no-input`, you are prompted for input:

  - Prompts are the keys in `cookiecutter.json`.
  - Default responses are the values in `cookiecutter.json`.
  - Prompts are shown in order.

* Cross-platform support for `~/.cookiecutterrc` files:

    .. code-block:: yaml

        default_context:
            full_name: "Audrey Roy"
            email: "audreyr@gmail.com"
            github_username: "audreyr"
        cookiecutters_dir: "~/.cookiecutters/"

* Cookiecutters (cloned Cookiecutter project templates) are put into
  `~/.cookiecutters/` by default, or cookiecutters_dir if specified.

* You can use local cookiecutters, or remote cookiecutters directly from Git
  repos or from Mercurial repos on Bitbucket.

* Default context: specify key/value pairs that you want used as defaults
  whenever you generate a project

* Direct access to the Cookiecutter API allows for injection of extra context.

* Pre- and post-generate hooks: Python or shell scripts to run before or after
  generating a project.

* Paths to local projects can be specified as absolute or relative.

* Projects are always generated to your current directory.

Available Cookiecutters
-----------------------

Here is a list of **cookiecutters** (aka Cookiecutter project templates) for you to use or fork.

Make your own, then submit a pull request adding yours to this list!

Python
~~~~~~
* `cookiecutter-pypackage`_: `@audreyr`_'s ultimate Python package project
  template.
* `cookiecutter-flask`_ : A Flask template with Bootstrap 3, starter templates, and working user registration.
* `cookiecutter-flask-foundation`_ : Flask Template with caching, forms, sqlalchemy and unit-testing.
* `cookiecutter-bottle`_ : A cookiecutter template for creating reusable Bottle projects quickly.
* `cookiecutter-openstack`_: A template for an OpenStack project.
* `cookiecutter-docopt`_: A template for a Python command-line script that uses `docopt`_ for arguments parsing.
* `cookiecutter-quokka-module`_: A template to create a blueprint module for Quokka Flask CMS.
* `cookiecutter-kivy`_: A template for NUI applications built upon the kivy python-framework.
* `cookiedozer`_: A template for Python Kivy apps ready to be deployed to android devices with Buildozer.
* `cookiecutter-pypackage-minimal`_: A mimimal Python package template.
* `cookiecutter-ansible-role`_: A template to create ansible roles. Forget about file creation and focus on actions.
* `cookiecutter-pylibrary`_: An intricate template designed to quickly get started with good testing and packaging (working configuration for Tox, Pytest, Travis-CI, Coveralls, AppVeyor, Sphinx docs, isort, bumpversion, packaging checks etc).
* `cookiecutter-pylibrary-minimal`_: Same as above but without Pytest and static configuration for Tox/Travis/AppVeyor (no generator).
* `cookiecutter-pyvanguard`_: A template for cutting edge Python development. `Invoke`_, pytest, bumpversion, and Python 2/3 compatability.
* `Python-iOS-template`_: A template to create a Python project that will run on iOS devices.
* `Python-Android-template`_: A template to create a Python project that will run on Android devices.
* `cookiecutter-tryton`_: A template for creating tryton modules.
* `cookiecutter-pytest-plugin`_: Minimal Cookiecutter template for authoring `pytest`_ plugins that help you to write better programs.
* `cookiecutter-tapioca`_: A Template for building `tapioca-wrapper`_ based web API wrappers (clients).
* `cookiecutter-sublime-text-3-plugin`_: Sublime Text 3 plugin template with custom settings, commands, key bindings and main menu.
* `cookiecutter-muffin`_: A Muffin template with Bootstrap 3, starter templates, and working user registration.

Python-Django
^^^^^^^^^^^^^

* `cookiecutter-django-rest`_: For creating REST apis for mobile and web applications.
* `cookiecutter-simple-django`_: A cookiecutter template for creating reusable Django projects quickly.
* `cookiecutter-django`_: A bleeding edge Django project template with Bootstrap 3, customizable users app, starter templates, and working user registration.
* `cookiecutter-djangopackage`_: A template designed to create reusable third-party PyPI friendly Django apps. Documentation is written in tutorial format.
* `cookiecutter-django-cms`_: A template for Django CMS with simple Bootstrap 3 template. It has a quick start and deploy documentation.
* `cookiecutter-djangocms-plugin`_: A template to get started with custom plugins for django-cms
* `cookiecutter-django-crud`_: A template to create a Django app with boilerplate CRUD around a model including a factory and tests.
* `cookiecutter-django-lborgav`_: Another cookiecutter template for Django project with Booststrap 3 and FontAwesome 4
* `cookiecutter-django-paas`_: Django template ready to use in SAAS platforms like Heroku, OpenShift, etc..
* `cookiecutter-django-rest-framework`_: A template for creating reusable Django REST Framework packages.
* `cookiecutter-wagtail`_ : A cookiecutter template for `Wagtail`_ CMS based sites.

C
~~

* `bootstrap.c`_: A template for simple projects written in C with autotools.
* `cookiecutter-avr`_: A template for avr development.

C++
~~~

* `BoilerplatePP`_: A simple cmake template with unit testing for projects written in C++.

C#
~~

* `cookiecutter-csharp-objc-binding`_: A template for generating a C# binding project for binding an Objective-C static library.

.. _`cookiecutter-csharp-objc-binding`: https://github.com/SandyChapman/cookiecutter-csharp-objc-binding

Common Lisp
~~~~~~~~~~~

* `cookiecutter-cl-project`_: A template for Common Lisp project with bootstrap script and Slime integration.

JS
~~

* `cookiecutter-es6-boilerplate`_: A cookiecutter for front end projects in ES6.
* `cookiecutter-jquery`_: A jQuery plugin project template based on jQuery
  Boilerplate.
* `cookiecutter-jswidget`_: A project template for creating a generic front-end,
  non-jQuery JS widget packaged for multiple JS packaging systems.
* `cookiecutter-component`_: A template for a Component JS package.
* `cookiecutter-tampermonkey`_: A template for a TamperMonkey browser script.

LaTeX/XeTeX
~~~~~~~~~~~

* `pandoc-talk`_: A cookiecutter template for giving talks with pandoc and XeTeX.

* `cookiecutter-latex-article`_: A LaTeX template geared towards academic use.

* `cookiecutter-beamer`_: A template for a LaTeX Beamer presentation.


Berkshelf-Vagrant
~~~~~~~~~~~~~~~~~

* `slim-berkshelf-vagrant`_: A simple cookiecutter template with sane cookbook defaults for common vagrant/berkshelf cookbooks.


HTML
~~~~

* `cookiecutter-complexity`_: A cookiecutter for a Complexity static site with Bootstrap 3.
* `cookiecutter-tumblr-theme`_: A cookiecutter for a Tumblr theme project with GruntJS as concatination tool.

.. _`cookiecutter-django-rest`: https://github.com/agconti/cookiecutter-django-rest
.. _`cookiecutter-es6-boilerplate`: https://github.com/agconti/cookiecutter-es6-boilerplate
.. _`cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
.. _`cookiecutter-jquery`: https://github.com/audreyr/cookiecutter-jquery
.. _`cookiecutter-flask`: https://github.com/sloria/cookiecutter-flask
.. _`cookiecutter-flask-foundation`: https://github.com/JackStouffer/cookiecutter-Flask-Foundation
.. _`cookiecutter-bottle`: https://github.com/avelino/cookiecutter-bottle
.. _`cookiecutter-simple-django`: https://github.com/marcofucci/cookiecutter-simple-django
.. _`cookiecutter-django`: https://github.com/pydanny/cookiecutter-django
.. _`cookiecutter-djangopackage`: https://github.com/pydanny/cookiecutter-djangopackage
.. _`cookiecutter-django-cms`: https://github.com/palazzem/cookiecutter-django-cms
.. _`cookiecutter-djangocms-plugin`: https://github.com/mishbahr/cookiecutter-djangocms-plugin
.. _`cookiecutter-django-crud`: https://github.com/wildfish/cookiecutter-django-crud
.. _`cookiecutter-quokka-module`: https://github.com/pythonhub/cookiecutter-quokka-module
.. _`cookiecutter-django-lborgav`: https://github.com/lborgav/cookiecutter-django
.. _`cookiecutter-django-paas`: https://github.com/pbacterio/cookiecutter-django-paas
.. _`cookiecutter-kivy`: https://github.com/hackebrot/cookiecutter-kivy
.. _`cookiedozer`: https://github.com/hackebrot/cookiedozer
.. _`cookiecutter-pypackage-minimal`: https://github.com/borntyping/cookiecutter-pypackage-minimal
.. _`cookiecutter-ansible-role`: https://github.com/iknite/cookiecutter-ansible-role
.. _`bootstrap.c`: https://github.com/vincentbernat/bootstrap.c
.. _`BoilerplatePP`: https://github.com/Paspartout/BoilerplatePP
.. _`cookiecutter-openstack`: https://github.com/openstack-dev/cookiecutter
.. _`cookiecutter-component`: https://github.com/audreyr/cookiecutter-component
.. _`cookiecutter-tampermonkey`: https://github.com/christabor/cookiecutter-tampermonkey
.. _`cookiecutter-docopt`: https://github.com/sloria/cookiecutter-docopt
.. _`docopt`: http://docopt.org/
.. _`cookiecutter-jswidget`: https://github.com/audreyr/cookiecutter-jswidget
.. _`pandoc-talk`: https://github.com/larsyencken/pandoc-talk
.. _`cookiecutter-latex-article`: https://github.com/Kreger51/cookiecutter-latex-article
.. _`cookiecutter-complexity`: https://github.com/audreyr/cookiecutter-complexity
.. _`cookiecutter-cl-project`: https://github.com/svetlyak40wt/cookiecutter-cl-project
.. _`slim-berkshelf-vagrant`: https://github.com/mahmoudimus/cookiecutter-slim-berkshelf-vagrant
.. _`cookiecutter-avr`: https://github.com/solarnz/cookiecutter-avr
.. _`cookiecutter-tumblr-theme`: https://github.com/relekang/cookiecutter-tumblr-theme
.. _`cookiecutter-pylibrary`: https://github.com/ionelmc/cookiecutter-pylibrary
.. _`cookiecutter-pylibrary-minimal`: https://github.com/ionelmc/cookiecutter-pylibrary-minimal
.. _`cookiecutter-pyvanguard`: https://github.com/robinandeer/cookiecutter-pyvanguard
.. _`Python-iOS-template`: https://github.com/pybee/Python-iOS-template
.. _`Python-Android-template`: https://github.com/pybee/Python-Android-template
.. _`Invoke`: http://invoke.readthedocs.org/en/latest/
.. _`cookiecutter-django-rest-framework`: https://github.com/jpadilla/cookiecutter-django-rest-framework
.. _`cookiecutter-tryton`: https://github.com/fulfilio/cookiecutter-tryton
.. _`cookiecutter-beamer`: https://github.com/luismartingil/cookiecutter-beamer
.. _`cookiecutter-pytest-plugin`: https://github.com/pytest-dev/cookiecutter-pytest-plugin
.. _`pytest`: http://pytest.org/latest/
.. _`cookiecutter-tapioca`: https://github.com/vintasoftware/cookiecutter-tapioca
.. _`tapioca-wrapper`: https://github.com/vintasoftware/tapioca-wrapper
.. _`cookiecutter-sublime-text-3-plugin`: https://github.com/kkujawinski/cookiecutter-sublime-text-3-plugin
.. _`cookiecutter-muffin`: https://github.com/drgarcia1986/cookiecutter-muffin
.. _`cookiecutter-wagtail`: https://github.com/torchbox/cookiecutter-wagtail
.. _`Wagtail`: https://github.com/torchbox/wagtail

Scala
~~~~~

* `cookiecutter-scala-spark`_: A cookiecutter template for Apache Spark applications written in Scala.

.. _`cookiecutter-scala-spark`: https://github.com/jpzk/cookiecutter-scala-spark

6502 Assembly
~~~~~~~~~~~~~
* `cookiecutter-atari2600`_: A cookiecutter template for Atari2600 projects.

.. _`cookiecutter-atari2600`: https://github.com/joeyjoejoejr/cookiecutter-atari2600

Similar projects
----------------

* `Paste`_ has a create option that creates a skeleton project.

* `Diecutter`_: an API service that will give you back a configuration file from
  a template and variables.

* `Django`_'s `startproject` and `startapp` commands can take in a `--template`
  option.

* `python-packager`_: Creates Python packages from its own template, with
  configurable options.

* `Yeoman`_ has a Rails-inspired generator system that provides scaffolding
  for apps.

* `Pyramid`_'s `pcreate` command for creating Pyramid projects from scaffold templates.

* `mr.bob`_ is a filesystem template renderer, meant to deprecate tools such as
  paster and templer.

* `grunt-init`_ used to be built into Grunt and is now a standalone scaffolding tool
  to automate project creation.

* `scaffolt`_ consumes JSON generators with Handlebars support.

* `init-skeleton`_ clones or copies a repository, executes npm install and bower install and removes the .git directory.

* `Cog`_ python-based code generation toolkit developed by Ned Batchelder

* `Skaffold`_ python and json config based django/MVC generator, with some add-ons and integrations.

.. _`Paste`: http://pythonpaste.org/script/#paster-create
.. _`Diecutter`: https://github.com/novagile/diecutter
.. _`Django`: https://docs.djangoproject.com/en/1.5/ref/django-admin/#django-admin-startproject
.. _`python-packager`: https://github.com/fcurella/python-packager
.. _`Yeoman`: https://github.com/yeoman/generator
.. _`Pyramid`: http://docs.pylonsproject.org/projects/pyramid/en/latest/narr/scaffolding.html
.. _`mr.bob`: https://github.com/iElectric/mr.bob
.. _`grunt-init`: https://github.com/gruntjs/grunt-init
.. _`scaffolt`: https://github.com/paulmillr/scaffolt
.. _`init-skeleton`: https://github.com/paulmillr/init-skeleton
.. _`Cog`: https://bitbucket.org/ned/cog
.. _`Skaffold`: https://github.com/christabor/Skaffold


Community
---------

The core committer team is `@audreyr`_, `@pydanny`_, `@michaeljoseph`_,
`@pfmoore`_, and `@hackebrot`_. We
welcome you and invite you to participate.

Stuck? Try one of the following:

* See the `Troubleshooting`_ page.
* Ask for help on `Stack Overflow`_.
* You are strongly encouraged to `file an issue`_ about the problem, even if
  it's just "I can't get it to work on this cookiecutter" with a link to your
  cookiecutter. Don't worry about naming/pinpointing the issue properly.
* Ask for help in #cookiecutter if you must (but please try one of the other
  options first, so that others can benefit from the discussion)

Development on Cookiecutter is community-driven:

* Huge thanks to all the `contributors`_ who have pitched in to help make
  Cookiecutter an even better tool.
* Everyone is invited to contribute. Read the `contributing instructions`_,
  then get started.

Connect with other Cookiecutter contributors and users in IRC:

* #cookiecutter on irc.freenode.net (note: due to work and commitments,
  a core committer might not always be available)

Encouragement is unbelievably motivating. If you want more work done on
Cookiecutter, show support:

* Thank a core committer for their efforts.
* Star `Cookiecutter on GitHub`_.
* Join the `Cookiecutter Gittip community`_.

Got criticism or complaints?

* `File an issue`_ so that Cookiecutter can be improved. Be friendly
  and constructive about what could be better. Make detailed suggestions.
* **Keep us in the loop so that we can help.** For example, if you are
  discussing problems with Cookiecutter on a mailing list, `file an issue`_
  where you link to the discussion thread and/or cc at least 1 core committer on
  the email.
* Be encouraging. A comment like "This function ought to be rewritten like
  this" is much more likely to result in action than a comment like "Eww, look
  how bad this function is."

Waiting for a response to an issue/question?

* Be patient and persistent. All issues are on the core committer team's radar and
  will be considered thoughtfully, but we have a lot of issues to work through. If
  urgent, it's fine to ping a core committer in the issue with a reminder.
* Ask others to comment, discuss, review, etc.
* Search the Cookiecutter repo for issues related to yours.
* Need a fix/feature/release/help urgently, and can't wait? `@audreyr`_ is
  available for hire for consultation or custom development.

Code of Conduct
---------------

Everyone interacting in the Cookiecutter project's codebases, issue trackers, chat
rooms, and mailing lists is expected to follow the `PyPA Code of Conduct`_.

.. _`PyPA Code of Conduct`: https://www.pypa.io/en/latest/code-of-conduct/

.. _`Cookiecutter on GitHub`: https://github.com/audreyr/cookiecutter
.. _`Troubleshooting`: http://cookiecutter.readthedocs.org/en/latest/troubleshooting.html
.. _`contributors`: https://github.com/audreyr/cookiecutter/blob/master/AUTHORS.rst
.. _`contributing instructions`: https://github.com/audreyr/cookiecutter/blob/master/CONTRIBUTING.rst
.. _`Stack Overflow`: http://stackoverflow.com/
.. _`File an issue`: https://github.com/audreyr/cookiecutter/issues?state=open
.. _`Cookiecutter Gittip community`: https://www.gittip.com/for/cookiecutter/
.. _`@audreyr`: https://github.com/audreyr
.. _`@pydanny`: https://github.com/pydanny
.. _`@michaeljoseph`: https://github.com/michaeljoseph
.. _`@pfmoore`: https://github.com/pfmoore
.. _`@hackebrot`: https://github.com/hackebrot




History
-------

1.1.0 (2015-09-26)
~~~~~~~~~~~~~~~~~~~~~~~~

The goals of this release is to add extra content via the command-line and `copy without render`_.

Features:

* Added `copy without render`_ feature, making it much easier for developers of Ansible, Salt Stack, and other recipe-based tools to work with Cookiecutter. Thanks to `@osantana`_ and `@LucianU`_ for their innovation, as well as `@hackebrot`_ for fixing the Windows problems (#132, #184, #425).
* Added `specify output directory`, thanks to `tony` and `@hackebrot`_ (#531, #452),
* Abort template rendering if the project output directory already exists, thanks to `@lgp171188`_ (#470, #471).
* Add a flag to overwrite existing output directory, thanks to `@lgp171188`_ for the implementation (#495) and `@schacki`_, `@ionelmc`_, `@pydanny`_ and `@hackebrot`_ for submitting issues and code reviews (#475, #493).
* Remove test command in favor of tox, thanks to `@hackebrot`_ (#480).
* Allow cookiecutter invocation, even without installing it, via ``python -m cookiecutter.cli``, thanks to  `@vincentbernat`_ and `@hackebrot`_ (#449, #487).
* Improve the type detection handler for online and offline repositories, thanks to `@charlax`_ (#490).
* Add replay feature, thanks to `@hackebrot`_ (#501).
* Be more precise when raising an error for an invalid user config file, thanks to `@vaab`_ and `@hackebrot`_ (#378, #528).
* Added official Python 3.5 support, thanks to `@pydanny`_ and `@hackebrot`_ (#522).

Other Changes:

* Updated click requirement to < 6.0, thanks to `@pydanny`_ (#473).
* Added landscape.io flair, thanks to `@michaeljoseph`_ (#439).
* Descriptions of PEP8 specifications and milestone management, thanks to `@michaeljoseph`_ (#440).
* Added alternate installation options in the documentation, thanks to `@pydanny`_  (#117, #315).
* The test of the `which()` function now tests against the `date` command, thanks to `@vincentbernat`_ (#446)
* Ensure file handles in setup.py are closed using with statement, thanks to `@svisser`_ (#280).
* Removed deprecated and fully extraneous `compat.is_exe()` function, thanks to `@hackebrot`_ (#485).
* Disabled sudo in .travis, thanks to `@hackebrot`_ (#482).
* Switched to shields.io for problematic badges, thanks to `@pydanny`_ (#491).
* Added whichcraft and removed ``compat.which()``, thanks to `@pydanny`_ (#511).
* Changed to export tox environment variables to codecov, thanks to `@maiksensi`_. (#508).
* Moved to using click version command, thanks to `@hackebrot`_ (#489).
* Don't use unicode_literals to please click, thanks to `@vincentbernat`_ (#503).
* Remove warning for Python 2.6 from __init__.py, thanks to `@hackebrot`_.
* Removed `compat.py` module, thanks to `@hackebrot`_.
* Added `future` to requirements, thanks to `@hackebrot`_.
* Fixed problem where expanduser does not resolve "~" correctly on windows 10 using tox, thanks to `@maiksensi`_. (#527)
* Added more cookiecutter templates to the mix:

  * `cookiecutter-beamer`_ by `@luismartingil`_ (#307)
  * `cookiecutter-pytest-plugin`_ by `@pytest-dev`_ and `@hackebrot`_ (#481)
  * `cookiecutter-csharp-objc-binding`_ by `@SandyChapman`_ (#460)
  * `cookiecutter-flask-foundation`_ by `@JackStouffer`_ (#457)
  * `cookiecutter-tryton`_ by `@fulfilio`_ (#465)
  * `cookiecutter-tapioca`_ by `@vintasoftware`_ (#496)
  * `cookiecutter-sublime-text-3-plugin`_ by `@kkujawinski`_ (#500)
  * `cookiecutter-muffin`_ by `@drgarcia1986`_ (#494)
  * `cookiecutter-django-rest`_ by `@agconti`_ (#520)
  * `cookiecutter-es6-boilerplate`_ by `@agconti`_ (#521)
  * `cookiecutter-tampermonkey`_ by `@christabor`_ (#516)
  * `cookiecutter-wagtail`_ by `@torchbox`_ (#533)

.. _`@maiksensi`: https://github.com/maiksensi
.. _`copy without render`: http://cookiecutter.readthedocs.org/en/latest/advanced_usage.html#copy-without-render
.. _`@osantana`: https://github.com/osantana
.. _`@LucianU`: https://github.com/LucianU
.. _`@svisser`: https://github.com/svisser
.. _`@lgp171188`: https://github.com/lgp171188
.. _`@SandyChapman`: https://github.com/SandyChapman
.. _`@JackStouffer`: https://github.com/JackStouffer
.. _`@fulfilio`: https://github.com/fulfilio
.. _`@vintasoftware`: https://github.com/vintasoftware
.. _`@kkujawinski`: https://github.com/kkujawinski
.. _`@charlax`: https://github.com/charlax
.. _`@drgarcia1986`: https://github.com/drgarcia1986
.. _`@agconti`: https://github.com/agconti
.. _`@vaab`: https://github.com/vaab
.. _`@christabor`: https://github.com/christabor
.. _`@torchbox`: https://github.com/torchbox

.. _`cookiecutter-beamer`: https://github.com/luismartingil/cookiecutter-beamer
.. _`@luismartingil`: https://github.com/luismartingil
.. _`cookiecutter-pytest-plugin`: https://github.com/pytest-dev/cookiecutter-pytest-plugin
.. _`@pytest-dev`: https://github.com/pytest-dev
.. _`cookiecutter-csharp-objc-binding`: https://github.com/SandyChapman/cookiecutter-csharp-objc-binding
.. _`cookiecutter-flask-foundation`: https://github.com/JackStouffer/cookiecutter-Flask-Foundation
.. _`cookiecutter-tryton`: https://github.com/fulfilio/cookiecutter-tryton
.. _`cookiecutter-tapioca`: https://github.com/vintasoftware/cookiecutter-tapioca
.. _`cookiecutter-sublime-text-3-plugin`: https://github.com/kkujawinski/cookiecutter-sublime-text-3-plugin
.. _`cookiecutter-muffin`: https://github.com/drgarcia1986/cookiecutter-muffin
.. _`cookiecutter-django-rest`: https://github.com/agconti/cookiecutter-django-rest
.. _`cookiecutter-es6-boilerplate`: https://github.com/agconti/cookiecutter-es6-boilerplate
.. _`cookiecutter-tampermonkey`: https://github.com/christabor/cookiecutter-tampermonkey
.. _`cookiecutter-wagtail`: https://github.com/torchbox/cookiecutter-wagtail

1.0.0 (2015-03-13) Chocolate Chip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The goals of this release was to formally remove support for Python 2.6 and continue the move to using py.test.

Features:

* Convert the unittest suite to py.test for the sake of comprehensibility, thanks to `@hackebrot`_ (#322, #332, #334, #336, #337, #338, #340, #341, #343, #345, #347, #351, #412, #413, #414).
* Generate pytest coverage, thanks to `@michaeljoseph`_ (#326).
* Documenting of Pull Request merging and HISTORY.rst maintenance, thanks to `@michaeljoseph`_ (#330).
* Large expansions to the tutorials thanks to `@hackebrot`_ (#384)
* Switch to using Click for command-line options, thanks to `@michaeljoseph`_ (#391, #393).
* Added support for working with private repos, thanks to `@marctc`_ (#265).
* Wheel configuration thanks to `@michaeljoseph`_ (#118).

Other Changes:

* Formally removed support for 2.6, thanks to `@pydanny`_ (#201).
* Moved to codecov for continuous integration test coverage and badges, thanks to `@michaeljoseph`_ (#71, #369).
* Made JSON parsing errors easier to debug, thanks to `@rsyring`_ and `@mark0978`_ (#355, #358, #388).
* Updated to Jinja 2.7 or higher in order to control trailing new lines in templates, thanks to `@sfermigier`_ (#356).
* Tweaked flake8 to ignore e731, thanks to `@michaeljoseph`_ (#390).
* Fixed failing Windows tests and corrected AppVeyor badge link thanks to `@msabramo`_ (#403).
* Added more Cookiecutters to the list:

  * `cookiecutter-scala-spark`_ by `@jpzk`_
  * `cookiecutter-atari2600`_ by `@joeyjoejoejr`_
  * `cookiecutter-bottle`_ by `@avelino`_
  * `cookiecutter-latex-article`_ by `@Kreger51`_
  * `cookiecutter-django-rest-framework`_ by `@jpadilla`_
  * `cookiedozer`_ by `@hackebrot`_

.. _`@msabramo`: https://github.com/msabramo
.. _`@marctc`: https://github.com/marctc
.. _`cookiedozer`: https://github.com/hackebrot/cookiedozer
.. _`@jpadilla`: https://github.com/jpadilla
.. _`cookiecutter-django-rest-framework`: https://github.com/jpadilla/cookiecutter-django-rest-framework
.. _`cookiecutter-latex-article`: https://github.com/Kreger51/cookiecutter-latex-article
.. _`@Kreger51`: https://github.com/Kreger51
.. _`@rsyring`: https://github.com/rsyring
.. _`@mark0978`: https://github.com/mark0978
.. _`cookiecutter-bottle`: https://github.com/avelino/cookiecutter-bottle
.. _`@avelino`: https://github.com/avelino
.. _`@joeyjoejoejr`: https://github.com/joeyjoejoejr
.. _`cookiecutter-atari2600`: https://github.com/joeyjoejoejr/cookiecutter-atari2600
.. _`@sfermigier`: https://github.com/sfermigier
.. _`cookiecutter-scala-spark`: https://github.com/jpzk/cookiecutter-scala-spark
.. _`@jpzk`: https://github.com/jpzk

0.9.0 (2015-01-13)
~~~~~~~~~~~~~~~~~~~

The goals of this release were to add the ability to Jinja2ify the `cookiecutter.json` default values, and formally launch support for Python 3.4.

Features:

* Python 3.4 is now a first class citizen, thanks to everyone.
* `cookiecutter.json` values are now rendered Jinja2 templates, thanks to @bollwyvl (#291).
* Move to `py.test`, thanks to `@pfmoore`_ (#319) and `@ramiroluz`_ (#310).
* Add `PendingDeprecation` warning for users of Python 2.6, as support for it is gone in Python 2.7, thanks to `@michaeljoseph`_ (#201).

Bug Fixes:

* Corrected typo in `Makefile`, thanks to `@inglesp`_ (#297).
* Raise an exception when users don't have `git` or `hg` installed, thanks to `@pydanny`_ (#303).

Other changes:

* Creation of `gitter`_ account for logged chat, thanks to `@michaeljoseph`_.
* Added ReadTheDocs badge, thanks to `@michaeljoseph`_.
* Added AppVeyor badge, thanks to `@pydanny`_
* Documentation and PyPI trove classifier updates, thanks to `@thedrow`_ (#323 and #324)

.. _`gitter`: https://gitter.im/audreyr/cookiecutter
.. _`@inglesp`: https://github.com/inglesp
.. _`@ramiroluz`: https://github.com/ramiroluz
.. _`@thedrow`: https://github.com/thedrow
.. _`@hackebrot`: https://github.com/hackebrot

0.8.0 (2014-10-30)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The goal of this release was to allow for injection of extra context via the
Cookiecutter API, and to fix minor bugs.

Features:

* `cookiecutter()` now takes an optional `extra_context` parameter, thanks to `@michaeljoseph`_, `@fcurella`_, `@aventurella`_, `@emonty`_, `@schacki`_, `@ryanolson`_, `@pfmoore`_, `@pydanny`_, `@audreyr`_ (#260).
* Context is now injected into hooks, thanks to `@michaeljoseph`_ and `@dinopetrone`_.
* Moved all Python 2/3 compatability code into `cookiecutter.compat`, making the eventual move to `six` easier, thanks to `@michaeljoseph`_ (#60, #102).
* Added `cookiecutterrc` defined aliases for cookiecutters, thanks to `@pfmoore`_ (#246)
* Added `flake8` to tox to check for pep8 violations, thanks to `@natim`_.

Bug Fixes:

* Newlines at the end of files are no longer stripped, thanks to `@treyhunner`_ (#183).
* Cloning prompt suppressed by respecting the `no_input` flag, thanks to `@trustrachel`_ (#285)
* With Python 3, input is no longer converted to bytes, thanks to `@uranusjr`_ (#98).

Other Changes:

* Added more Cookiecutters to the list:

  * `Python-iOS-template`_ by `@freakboy3742`_
  * `Python-Android-template`_ by `@freakboy3742`_
  * `cookiecutter-djangocms-plugin`_ by `@mishbahr`_
  * `cookiecutter-pyvanguard`_ by `@robinandeer`_

.. _`Python-iOS-template`: https://github.com/pybee/Python-iOS-template
.. _`Python-Android-template`: https://github.com/pybee/Python-Android-template
.. _`cookiecutter-djangocms-plugin`: https://github.com/mishbahr/cookiecutter-djangocms-plugin
.. _`cookiecutter-pyvanguard`: https://github.com/robinandeer/cookiecutter-pyvanguard

.. _`@trustrachel`: https://github.com/trustrachel
.. _`@robinandeer`: https://github.com/robinandeer
.. _`@mishbahr`: https://github.com/mishbahr
.. _`@freakboy3742`: https://github.com/freakboy3742
.. _`@treyhunner`: https://github.com/treyhunner
.. _`@pfmoore`: https://github.com/pfmoore
.. _`@fcurella`: https://github.com/fcurella
.. _`@aventurella`: https://github.com/aventurella
.. _`@emonty`: https://github.com/emonty
.. _`@schacki`: https://github.com/schacki
.. _`@ryanolson`: https://github.com/ryanolson
.. _`@Natim`: https://github.com/Natim
.. _`@dinopetrone`: https://github.com/dinopetrone

0.7.2 (2014-08-05)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The goal of this release was to fix cross-platform compatibility, primarily
Windows bugs that had crept in during the addition of new features. As of this
release, Windows is a first-class citizen again, now complete with continuous
integration.

Bug Fixes:

* Fixed the contributing file so it displays nicely in Github, thanks to `@pydanny`_.
* Updates 2.6 requirements to include simplejson, thanks to `@saxix`_.
* Avoid unwanted extra spaces in string literal, thanks to `@merwok`_.
* Fix `@unittest.skipIf` error on Python 2.6.
* Let sphinx parse `:param:` properly by inserting newlines #213, thanks to `@mineo`_.
* Fixed Windows test prompt failure by replacing stdin per `@cjrh`_ in #195.
* Made rmtree remove readonly files, thanks to `@pfmoore`_.
* Now using tox to run tests on Appveyor, thanks to `@pfmoore`_ (#241).
* Fixed tests that assumed the system encoding was utf-8, thanks to `@pfmoore`_ (#242, #244).
* Added a tox ini file that uses py.test, thanks to `@pfmoore`_ (#245).

.. _`@merwok`: https://github.com/merwok
.. _`@mineo`: https://github.com/mineo
.. _`@cjrh`: https://github.com/cjrh

Other Changes:

* `@audreyr`_ formally accepted position as **BDFL of cookiecutter**.
* Elevated `@pydanny`_, `@michaeljoseph`_, and `@pfmoore`_ to core committer status.
* Added Core Committer guide, by `@audreyr`_.
* Generated apidocs from `make docs`, by `@audreyr`_.
* Added `contributing` command to the `make docs` function, by `@pydanny`_.
* Refactored contributing documentation, included adding core committer instructions, by `@pydanny`_ and `@audreyr`_.
* Do not convert input prompt to bytes, thanks to `@uranusjr`_ (#192).
* Added troubleshooting info about Python 3.3 tests and tox.
* Added documentation about command line arguments, thanks to `@saxix`_.
* Style cleanups.
* Added environment variable to disable network tests for environments without networking, thanks to `@vincentbernat`_.
* Added Appveyor support to aid Windows integrations, thanks to `@pydanny`_ (#215).
* CONTRIBUTING.rst is now generated via `make contributing`, thanks to `@pydanny`_ (#220).
* Removed unnecessary endoing argument to `json.load`, thanks to `@pfmoore`_ (#234).
* Now generating shell hooks dynamically for Unix/Windows portability, thanks to `@pfmoore`_ (#236).
* Removed non-portable assumptions about directory structure, thanks to `@pfmoore`_ (#238).
* Added a note on portability to the hooks documentation, thanks to `@pfmoore`_ (#239).
* Replaced `unicode_open` with direct use of `io.open`, thanks to `@pfmoore`_ (#229).
* Added more Cookiecutters to the list:

  * `cookiecutter-kivy`_ by `@hackebrot`_
  * BoilerplatePP_ by `@Paspartout`_
  * `cookiecutter-pypackage-minimal`_ by `@borntyping`_
  * `cookiecutter-ansible-role`_ by `@iknite`_
  * `cookiecutter-pylibrary`_ by `@ionelmc`_
  * `cookiecutter-pylibrary-minimal`_ by `@ionelmc`_


.. _`cookiecutter-kivy`: https://github.com/hackebrot/cookiecutter-kivy
.. _`cookiecutter-ansible-role`: https://github.com/iknite/cookiecutter-ansible-role
.. _BoilerplatePP: https://github.com/Paspartout/BoilerplatePP
.. _`cookiecutter-pypackage-minimal`: https://github.com/borntyping/cookiecutter-pypackage-minimal
.. _`cookiecutter-pylibrary`: https://github.com/ionelmc/cookiecutter-pylibrary
.. _`cookiecutter-pylibrary-minimal`: https://github.com/ionelmc/cookiecutter-pylibrary-minimal

.. _`@Paspartout`: https://github.com/Paspartout
.. _`@audreyr`: https://github.com/audreyr
.. _`@borntyping`: https://github.com/borntyping
.. _`@hackebrot`: https://github.com/hackebrot
.. _`@iknite`: https://github.com/iknite
.. _`@ionelmc`: https://github.com/ionelmc
.. _`@michaeljoseph`: https://github.com/michaeljoseph
.. _`@pfmoore`: https://github.com/pfmoore
.. _`@pydanny`: https://github.com/pydanny
.. _`@saxix`: https://github.com/saxix
.. _`@uranusjr`: https://github.com/uranusjr



0.7.1 (2014-04-26)
~~~~~~~~~~~~~~~~~~~~~~~~~~

Bug fixes:

* Use the current Python interpreter to run Python hooks, thanks to
  `@coderanger`_.
* Include tests and documentation in source distribution, thanks to
  `@vincentbernat`_.
* Fix various warnings and missing things in the docs (#129, #130),
  thanks to `@nedbat`_.
* Add command line option to get version (#89), thanks to `@davedash`_
  and `@cyberj`_.

Other changes:

* Add more Cookiecutters to the list:

  * `cookiecutter-avr`_ by `@solarnz`_
  * `cookiecutter-tumblr-theme`_ by `@relekang`_
  * `cookiecutter-django-paas`_ by `@pbacterio`_

.. _`@coderanger`: https://github.com/coderanger
.. _`@vincentbernat`: https://github.com/vincentbernat
.. _`@nedbat`: https://github.com/nedbat
.. _`@davedash`: https://github.com/davedash
.. _`@cyberj`: https://github.com/cyberj

.. _`cookiecutter-avr`: https://github.com/solarnz/cookiecutter-avr
.. _`@solarnz`: https://github.com/solarnz
.. _`cookiecutter-tumblr-theme`: https://github.com/relekang/cookiecutter-tumblr-theme
.. _`@relekang`: https://github.com/relekang
.. _`cookiecutter-django-paas`: https://github.com/pbacterio/cookiecutter-django-paas
.. _`@pbacterio`: https://github.com/pbacterio

0.7.0 (2013-11-09)
~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a release with significant improvements and changes. Please read
through this list before you upgrade.

New features:

* Support for --checkout argument, thanks to `@foobacca`_.
* Support for pre-generate and post-generate hooks, thanks to `@raphigaziano`_.
  Hooks are Python or shell scripts that run before and/or after your project
  is generated.
* Support for absolute paths to cookiecutters, thanks to `@krallin`_.
* Support for Mercurial version control system, thanks to `@pokoli`_.
* When a cookiecutter contains invalid Jinja2 syntax, you get a better message
  that shows the location of the TemplateSyntaxError. Thanks to `@benjixx`_.
* Can now prompt the user to enter values during generation from a local
  cookiecutter, thanks to `@ThomasChiroux`_. This is now always the default
  behavior. Prompts can also be supressed with `--no-input`.
* Your cloned cookiecutters are stored by default in your `~/.cookiecutters/`
  directory (or Windows equivalent). The location is configurable. (This is a
  major change from the pre-0.7.0 behavior, where cloned cookiecutters were
  deleted at the end of project generation.) Thanks `@raphigaziano`_.
* User config in a `~/.cookiecutterrc` file, thanks to `@raphigaziano`_.
  Configurable settings are `cookiecutters_dir` and `default_context`.
* File permissions are now preserved during project generation, thanks to
  `@benjixx`_.

Bug fixes:

* Unicode issues with prompts and answers are fixed, thanks to `@s-m-i-t-a`_.
* The test suite now runs on Windows, which was a major effort. Thanks to
  `@pydanny`_, who collaborated on this with me.

Other changes:

* Quite a bit of refactoring and API changes.
* Lots of documentation improvements. Thanks `@sloria`_, `@alex`_, `@pydanny`_,
  `@freakboy3742`_, `@es128`_, `@rolo`_.
* Better naming and organization of test suite.
* A `CookiecutterCleanSystemTestCase` to use for unit tests affected by the
  user's config and cookiecutters directory.
* Improvements to the project's Makefile.
* Improvements to tests. Thanks `@gperetin`_, `@s-m-i-t-a`_.
* Removal of `subprocess32` dependency. Now using non-context manager version
  of `subprocess.Popen` for Python 2 compatibility.
* Removal of cookiecutter's `cleanup` module.
* A bit of `setup.py` cleanup, thanks to `@oubiga`_.
* Now depends on binaryornot 0.2.0.

.. _`@foobacca`: https://github.com/foobacca/
.. _`@raphigaziano`: https://github.com/raphigaziano/
.. _`@gperetin`: https://github.com/gperetin/
.. _`@krallin`: https://github.com/krallin/
.. _`@pokoli`: https://github.com/pokoli/
.. _`@benjixx`: https://github.com/benjixx/
.. _`@ThomasChiroux`: https://github.com/ThomasChiroux/
.. _`@s-m-i-t-a`: https://github.com/s-m-i-t-a/
.. _`@sloria`: https://github.com/sloria/
.. _`@alex`: https://github.com/alex/
.. _`@es128`: https://github.com/es128/
.. _`@rolo`: https://github.com/rolo/
.. _`@oubiga`: https://github.com/oubiga/

0.6.4 (2013-08-21)
~~~~~~~~~~~~~~~~~~

* Windows support officially added.
* Fix TemplateNotFound Exception on Windows (#37).

0.6.3 (2013-08-20)
~~~~~~~~~~~~~~~~~~

* Fix copying of binary files in nested paths (#41), thanks to `@sloria`_.

.. _`@sloria`: https://github.com/sloria/

0.6.2 (2013-08-19)
~~~~~~~~~~~~~~~~~~

* Depend on Jinja2>=2.4 instead of Jinja2==2.7.
* Fix errors on attempt to render binary files. Copy them over from the project
  template without rendering.
* Fix Python 2.6/2.7 `UnicodeDecodeError` when values containing Unicode chars
  are in `cookiecutter.json`.
* Set encoding in Python 3 `unicode_open()` to always be utf-8.

0.6.1 (2013-08-12)
~~~~~~~~~~~~~~~~~~

* Improved project template finding. Now looks for the occurrence of `{{`,
  `cookiecutter`, and `}}` in a directory name.
* Fix help message for input_dir arg at command prompt.
* Minor edge cases found and corrected, as a result of improved test coverage.

0.6.0 (2013-08-08)
~~~~~~~~~~~~~~~~~~

* Config is now in a single `cookiecutter.json` instead of in `json/`.
* When you create a project from a git repo template, Cookiecutter prompts
  you to enter custom values for the fields defined in `cookiecutter.json`.

0.5 (2013-07-28)
~~~~~~~~~~~~~~~~~~

* Friendlier, more simplified command line usage::

    # Create project from the cookiecutter-pypackage/ template
    $ cookiecutter cookiecutter-pypackage/

    # Create project from the cookiecutter-pypackage.git repo template
    $ cookiecutter https://github.com/audreyr/cookiecutter-pypackage.git

* Can now use Cookiecutter from Python as a package::

    from cookiecutter.main import cookiecutter

    # Create project from the cookiecutter-pypackage/ template
    cookiecutter('cookiecutter-pypackage/')

    # Create project from the cookiecutter-pypackage.git repo template
    cookiecutter('https://github.com/audreyr/cookiecutter-pypackage.git')

* Internal refactor to remove any code that changes the working directory.

0.4 (2013-07-22)
~~~~~~~~~~~~~~~~~~

* Only takes in one argument now: the input directory. The output directory
  is generated by rendering the name of the input directory.
* Output directory cannot be the same as input directory.

0.3 (2013-07-17)
~~~~~~~~~~~~~~~~~~

* Takes in command line args for the input and output directories.

0.2.1 (2013-07-17)
~~~~~~~~~~~~~~~~~~

* Minor cleanup.

0.2 (2013-07-17)
~~~~~~~~~~~~~~~~~~

Bumped to "Development Status :: 3 - Alpha".

* Works with any type of text file.
* Directory names and filenames can be templated.

0.1.0 (2013-07-11)
~~~~~~~~~~~~~~~~~~

* First release on PyPI.

Roadmap
-------

https://github.com/audreyr/cookiecutter/milestones?direction=desc&sort=due_date&state=open


