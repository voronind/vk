#!/usr/bin/env python

from setuptools import setup, find_packages


setup(
    name='vk',
    version='2.0-beta',

    author='Dmitry Voronin',
    author_email='dimka665@gmail.com',

    url='https://github.com/dimka665/vk',
    description='vk.com API Python wrapper',

    packages=find_packages(),
    install_requires='requests',

    license='MIT License',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='vk.com api vk wrappper',
)
