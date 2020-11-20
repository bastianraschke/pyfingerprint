# ------------------------------------------------------------------------------
#  Created by Tyler Stegmaier.
#  Property of TrueLogic Company.
#  Copyright (c) 2020.
# ------------------------------------------------------------------------------

# !/usr/bin/env python
# -*- coding: utf-8 -*-

from .PyFingerPrint import *
from .__version__ import version




__doc__ = """
PyFingerprint
Copyright (C) 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
https://github.com/bastianraschke/pyfingerprint

Modified library:
https://github.com/Jakar510/pyfingerprint/blob/Development/src/files/pyfingerprint/pyfingerprint.py
"""

__name__ = 'pyfingerprint' or 'PythonFingerprint'
__author__ = "Tyler Stegmaier, Bastian Raschke"
__email__ = "tyler.stegmaier.510@gmail.com, bastian.raschke@posteo.de"
__copyright__ = "Copyright 2020"
__credits__ = [
        "Copyright (C) 2016 Bastian Raschke <bastian.raschke@posteo.de>",
        "Copyright (c) 2020 Tyler Stegmaier",
        ]
__license__ = "German Free Software License"
__version__ = version
__maintainer__ = __author__
__maintainer_email__ = __email__

# How mature is this project? Common values are
#   3 - Alpha
#   4 - Beta
#   5 - Production/Stable
__status__ = 'Development Status :: 4 - Beta'

__url__ = r'https://github.com/Jakar510/pyfingerprint'
# download_url=f'https://github.com/Jakar510/pyfingerprint/releases/tag/{version}'
__classifiers__ = [
        __status__,

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish
        'License :: MIT -- Free To Use But Restricted',

        # Support platforms
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',

        'Programming Language :: Python :: 3',
        ]

__short_description__ = """The PyFingerprint library allows to use of any ZhianTec ZFM-20, ZFM-60, ZFM-70 and ZFM-100 fingerprint sensors on the Raspberry Pi or other python capable 
machines. Other models like R302, R303, R305, R306, R307, R551 and FPM10A also work."""


# def _ChangeSerialSettings(func, tag: str = '__ChangeSerialSettings__'):
#     @functools.wraps(func)
#     def wrapped(self, *args, **kwargs):
#         args_repr = [repr(a) for a in args]  # 1
#         kwargs_repr = [f"{k}={v!r}" for k, v in kwargs.items()]  # 2
#         signature = ", ".join(args_repr + kwargs_repr)  # 3
#         print(f"\n{tag}.Calling {func.__name__}({signature})")
#         if self.__external_serial:
#             # self._serial.close()
#             self._serial.apply_settings(self._CommSettings)
#             # self._serial.open()
#             print(func.__name__)
#
#             result = func(self, *args, **kwargs)
#             # self._serial.close()
#             self._serial.apply_settings(self._oldSettings)
#             # self._serial.open()
#         else:
#             result = func(self, *args, **kwargs)
#         print(f"{func.__name__!r} returned {result!r}\n")  # 4
#         return result
#     return wrapped
