#!/usr/bin/env python

import os
import re

from setuptools import setup, find_packages


def get_version(file_rel_path):
    base_dir = os.path.dirname(__file__)
    file_abs_path = os.path.join(base_dir, file_rel_path)
    with open(file_abs_path) as file:
        file_content = file.read()
        version = re.findall(r"^__version__ = '(.+)'$", file_content, re.MULTILINE)[0]
        return version


setup(
    name='vk',
    version=get_version('vk/__init__.py'),

    author='Dmitry Voronin',
    author_email='dimka665@gmail.com',

    url='https://github.com/dimka665/vk',
    description='vk.com API Python wrapper',

    packages=find_packages(),
    install_requires='requests ~= 2.11',

    license='MIT License',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='vk.com api vk wrappper',
)
