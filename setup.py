#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
from setuptools import setup, find_packages
from os import path
this_directory = path.abspath(path.dirname(__file__))
with io.open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    desc = f.read()

# python setup.py bdist_wheel
# python -m pip install -e . 
# python setup.py sdist

# Build It
# python setup.py bdist_wheel sdist

# Push to PyPi
# python -m pip install twine
# twine upload dist/*

setup(
    name="Log4jScanner",
    version="1.2",
    description="Log4j CVE Vulnerability Scanner - Python Module",
    long_description=desc,
    long_description_content_type='text/markdown',
    author="Pushpender Singh",
    author_email="singhpushpender250@gmail.com",
    license='GNU General Public License v3 (GPLv3)',
    url='https://github.com/PushpenderIndia/Log4jScanner',
    py_modules=["Log4jScanner", "DNSCallBackProvider"],
    packages=find_packages(),
    package_data={'log4jscanner': ['db/*']},
    install_requires=[
        'requests',
        'PyCryptodome',
        'colorama',
        'pyfiglet',
        'argparse',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    entry_points={
        'console_scripts': [
            'log4jscanner = log4jscanner.Log4jScanner:main'
        ]
    },
    keywords=['log4jscanner', 'bug bounty', 'http', 'pentesting', 'security'],    
)