- create self signed certificate: openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
- optional: create venv: mkvirtualenv --no-site-packages --python=python2.7 oauth-server-test
- install: python setup.py install
- run with cert.pem: python authorization_code_grant.py /location/of/cert.pem
- go to: http://localhost:8081/app

NOTE: adapted from here: https://github.com/wndhydrnt/python-oauth2/blob/master/examples/authorization_code_grant.py