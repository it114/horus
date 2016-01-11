![](http://i.imgur.com/k0COvfS.jpg)

## horus

A mobile pentesting framework written in Python. It is intended to have to 2 major components:

 - [x] Static Analysis
 - [ ] Dynamic Analysis

## Installation

1. Clone the repository (`git clone https://github.com/delta24/horus`)
2. Install virtualenv. (the package name maybe different depending on the distro)
3. Set-up a virtualenv, say `env` by running `mkvirtualenv env -p /usr/bin/python2`.
4. Activate the virtualenv `source env/bin/activate`.
5. Install dependencies using `pip install -r requirements.txt`.
7. Run the application server using `python horus.py`.

## Screenshots

![1.png](http://i.imgur.com/gz9TFgB.png)

![2.png](http://i.imgur.com/ykdnbYZ.png)

![3.png](http://i.imgur.com/GVnk53h.png)

![4.png](http://i.imgur.com/g1UD9hY.png)

## ROADMAP

 - [ ] Run the scan separately from the main Flask thread (blocking) - Highest priority
 - [x] Refactor
 - [ ] PDF report generation


## TOOLS INCLUDED

androguard as the main static analyzer backend

androwarn

androbugs framework

## LICENSE

See the [LICENSE](https://github.com/delta24/horus/LICENSE) file
