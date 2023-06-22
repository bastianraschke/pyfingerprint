#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from pyfingerprint.pyfingerprint import PyFingerprint
#from pyfingerprint.pyfingerprint import FINGERPRINT_COMMANDPACKET
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_COLORS
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_COLORRED
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_COLORBLUE
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_COLORPURPLE
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_COLORYELLOW
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_COLORCYAN
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_COLORCOLDWHITE
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_COLORWARMWHITE
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_ALWAYSON
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_ALWAYSOFF
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_FLASHING
from pyfingerprint.pyfingerprint import FINGERPRINT_LEDCONTROL_BREATHING




## Tries to initialize the sensor
try:
    f = PyFingerprint('/dev/serial0', 57600, 0xFFFFFFFF, 0x00000000)

    if ( f.verifyPassword() == False ):
        raise ValueError('The given fingerprint sensor password is wrong!')

except Exception as e:
    print('The fingerprint sensor could not be initialized!')
    f.ledControl(FINGERPRINT_LEDCONTROL_COLORS.get("red"), FINGERPRINT_LEDCONTROL_BREATHING, 0, 2)
    print('Exception message: ' + str(e))
    exit(1)


try:
    f.ledControl(FINGERPRINT_LEDCONTROL_COLORS.get("warmwhite"), FINGERPRINT_LEDCONTROL_FLASHING, 5, 50)
    time.sleep(2)
    f.ledControl(FINGERPRINT_LEDCONTROL_COLORCYAN, FINGERPRINT_LEDCONTROL_FLASHING, 5, 50)
    time.sleep(1)
except Exception as e:
    print('Error with LED control')
    print('Exception message: ' + str(e))
    exit(1)
