#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from setuptools import setup

from src.files.pyfingerprint import __author__, __classifiers__, __email__, __license__, __name__, __short_description__, __url__, __version__, __maintainer_email__, __maintainer__



with open(os.path.abspath("requirements.txt"), "r") as f:
    install_requires = f.readlines()

with open('README.md', 'r') as readme:
    long_description = readme.read()

setup(name=__name__,
      version=__version__,
      packages=[__name__, f'{__name__}.Widgets', f'{__name__}.Misc', f'{__name__}.Events'],
      url=__url__,
      license=__license__,
      author=__author__,
      author_email=__email__,
      maintainer=__maintainer__,
      maintainer_email=__maintainer_email__,
      description=__short_description__,
      long_description=long_description,
      long_description_content_type="text/markdown",
      install_requires=install_requires,
      classifiers=__classifiers__,
      keywords=f'{__name__} fingeprint',
      package_dir={ f'{__name__}': f'src/files/{__name__}' },
      )


# setup(
#     name            = 'pyfingerprint',
#     author          = 'Bastian Raschke',
#     author_email    = 'bastian.raschke@posteo.de',
#     maintainer      = 'Philipp Meisberger',
#     maintainer_email= 'team@pm-codeworks.de',
#     description     = 'Python written library for using ZhianTec fingerprint sensors.',
#     long_description= long_description,
#     long_description_content_type='text/markdown',
#     url             = 'https://github.com/bastianraschke/pyfingerprint',
#     license         = 'D-FSL',
#     package_dir     = {'': 'files'},
#     packages        = ['pyfingerprint'],
#     install_requires= [
#         'pyserial',
#         'Pillow'
#     ],
#     classifiers     = [
#         'Development Status :: 5 - Production/Stable'
#         'Intended Audience :: Developers',
#         'Programming Language :: Python',
#         'Programming Language :: Python :: 2',
#         'Programming Language :: Python :: 3',
#         'Operating System :: OS Independent',
#         'Topic :: Terminals :: Serial',
#         'Topic :: Software Development :: Libraries :: Python Modules',
#     ]
# )
