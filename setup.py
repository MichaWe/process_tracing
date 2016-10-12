"""
A python-ptrace based configurable process tracer
that collects metadata about executed processes and allowes
in-depth analyzation

See:
TODO
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages

# To use a consistent encoding
from codecs import open
from os import path

pwd = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(pwd, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='process_tracing',

    version='0.0.1',

    description='ptrace based process tracing utilities for python',
    long_description=long_description,


)