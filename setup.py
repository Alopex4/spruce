#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

version = '0.1.1'

requires_lib = ['PyQt5>=5.12.1', 'requests>=2.21.0', 'netifaces>=0.10.9',
                'numpy>=1.11.0', 'matplotlib>=3.0.3', 'scapy>=2.4.0',
                'psutil>=3.4.2', 'ptable>=0.9.2']

setup(
    name='spruce-sniffer',
    version=version,
    author="alopex cheung",
    author_email="alopex4@163.com",
    description="spruce sniffer is a versatile network sniffer",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/Alopex4/spruce",
    license='MIT',
    packages=['src', 'src.capturePkt', 'src.dialogs', 'src.threads',
              'src.windows'],
    install_requires=requires_lib,
    classifiers=[
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Software Development :: Version Control :: Git',
    ],
    package_data={
        '': ['../../static/help.html', '../../static/oui.csv', '../../icon/*']},
    entry_points={'console_scripts': [
        'spruce = src.__main__:main',
    ]},
)
