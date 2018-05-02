#!/usr/bin/env python

from distutils.core import setup

setup(name='macattc',
      packages=['macattc'],
      version='1.0',
      description='get some free wifi boi',
      author='Josh Cristol',
      author_email='joshcristol@gmail.com',
      url='https://github.com/jcristol/macattc',
      download_url = 'https://github.com/jcristol/macattc/archive/1.0.tar.gz', 
      install_requires=['tqdm', 'netifaces', 'netaddr', 'netifaces', 'wireless'],
      keyword=['hacking'],
      entry_points = {
        'console_scripts': ['macattc=macattc.wifi:main'],
      },
     )
