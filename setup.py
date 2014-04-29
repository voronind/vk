#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='vk',
    version='1.5',

    author='Dmitry Voronin',
    author_email='dimka665@gmail.com',

    url='https://github.com/dimka665/vk',
    description='vk.com API Python wrapper',

    packages=find_packages(),
    install_requires='requests',

    license='MIT license',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='vk.com api vk vkontakte wrappper',
)
