#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import codecs
from setuptools import setup


def read(fname):
    file_path = os.path.join(os.path.dirname(__file__), fname)
    return codecs.open(file_path, encoding='utf-8').read()


setup(
    name='pytest-skipper',
    version='0.1.3',
    author='Pekka Pöyry',
    author_email='pekka.poyry@gmail.com',
    license='MIT',
    url='https://github.com/quantus/pytest-skipper',
    description=(
        'A plugin that selects only tests with changes in execution path'
    ),
    long_description=read('README.rst'),
    py_modules=['pytest_skipper'],
    install_requires=[
        'pytest>=3.0.6',
        'coverage>=4.2',
        'GitPython>=2.1.1'
        ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Framework :: Pytest',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Testing',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
    ],
    entry_points={
        'pytest11': [
            'pytest_skipper = pytest_skipper',
        ],
    },
)
