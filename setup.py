from setuptools import setup, find_packages

setup(name='python-oauth-test',
      version='1.0',
      description='Simple server to test Oauth2.0 flow',
      author='Semetric Ltd',
      author_email='dev@musicmetric.com',
      url='http://www.semetric.com',
      install_requires=["httplib2", "python-oauth2", "oauth2client"],
     )