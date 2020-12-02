# ------------------------------------------------------------------------------
#  Created by Tyler Stegmaier.
#  Property of TrueLogic Company.
#  Copyright (c) 2020.
# ------------------------------------------------------------------------------

# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PyFingerprint
Copyright (C) 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
https://github.com/bastianraschke/pyfingerprint

Modified library:
https://github.com/Jakar510/pyfingerprint/blob/Development/src/files/pyfingerprint/pyfingerprint.py
"""

import hashlib
import os
import struct
import time
from multiprocessing.connection import Connection
from threading import Event
from typing import Any, Dict, List, Tuple, Union

import serial
from PIL import Image

from .Constants import *




__all__ = ['PyFingerPrint', 'Result', 'Record']

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


class Result(object):
    """ [ Result.Success, positionNumber, accuracyScore ] """
    Success: bool
    Position: int
    AccuracyScore: int
    def __init__(self, success: bool, pos: int, accuracy: int):
        self.Success = success
        self.Position = pos
        self.AccuracyScore = accuracy
class SystemParameters(object):
    """
     {
        'statusRegister':  statusRegister,
        'baudRate':        baudRate,
        'packetLength':    packetLength,
        'deviceAddress':   deviceAddress,
        'securityLevel':   securityLevel,
        'storageCapacity': storageCapacity,
        'systemID':        systemID
    }
    """
    __slots__ = ['__data']
    __data: dict
    def __init__(self, cfg):
        self.__data: dict = { }
        if isinstance(cfg, tuple):
            statusRegister, systemID, storageCapacity, securityLevel, deviceAddress, packetLength, baudRate = cfg
            self.__data.update({
                    'statusRegister':  statusRegister,
                    'baudRate':        baudRate,
                    'packetLength':    packetLength,
                    'deviceAddress':   deviceAddress,
                    'securityLevel':   securityLevel,
                    'storageCapacity': storageCapacity,
                    'systemID':        systemID
                    })

        elif isinstance(cfg, dict):
            self.__data = cfg

    @property
    def statusRegister(self) -> int: return self.__data['statusRegister']
    @statusRegister.setter
    def statusRegister(self, value: int): self.__data['statusRegister'] = value

    @property
    def baudRate(self) -> int: return self.__data['baudRate']
    @baudRate.setter
    def baudRate(self, value: int): self.__data['baudRate'] = value

    @property
    def packetLength(self) -> int: return self.__data['packetLength']
    @packetLength.setter
    def packetLength(self, value: int): self.__data['packetLength'] = value

    @property
    def deviceAddress(self) -> int: return self.__data['deviceAddress']
    @deviceAddress.setter
    def deviceAddress(self, value: int): self.__data['deviceAddress'] = value

    @property
    def securityLevel(self) -> int: return self.__data['securityLevel']
    @securityLevel.setter
    def securityLevel(self, value: int): self.__data['securityLevel'] = value

    @property
    def storageCapacity(self) -> int: return self.__data['storageCapacity']
    @storageCapacity.setter
    def storageCapacity(self, value: int): self.__data['storageCapacity'] = value

    @property
    def systemID(self) -> int: return self.__data['systemID']
    @systemID.setter
    def systemID(self, value: int): self.__data['systemID'] = value

    def ToTuple(self) -> tuple: return self.statusRegister, self.systemID, self.storageCapacity, self.securityLevel, self.deviceAddress, self.packetLength, self.baudRate


class Record(dict):
    def __init__(self, pos: int, hashed: str, characteristics: List[int]):
        super().__init__(position_number=pos, hashed=hashed, characteristics=characteristics)

    @property
    def position_number(self) -> int: return self.get('position_number')
    @property
    def hashed(self) -> str: return self.get('hashed')
    @property
    def characteristics(self) -> List[int]: return self.get('characteristics')

default_port: str = '/dev/ttyS0'
class PyFingerPrint(object):
    """
    A python written library for the ZhianTec ZFM-20 fingerprint sensor.

    @attribute integer(4 bytes) _address
    Address to connect to sensor.

    @attribute integer(4 bytes) _password
    Password to connect to sensor.

    @attribute Serial _serial
    UART serial connection via PySerial.
    """
    _address: hex = None
    _password: hex = None
    _sensor_settings: SystemParameters or None = None
    _serial: serial.Serial or None = None
    DefaultBaudRate = 57600
    # dict(port=None, baudrate=DefaultBaudRate, bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=None,
    #      xonxoff=False, rtscts=False, write_timeout=None, dsrdtr=False, inter_byte_timeout=None, exclusive=None, writeTimeout=None, interCharTimeout=None)
    _DefaultSerialSettings = dict(baudrate=DefaultBaudRate, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=0)
    def __init__(self, Serial: serial.Serial = None, *, address: hex = MAX_ADDRESS, password: hex = MIN_ADDRESS):
        """
            Constructor

        :param address: integer(4 bytes)
        :param password: integer(4 bytes)
        """
        # BaudRate: int = 57600,  if BaudRate < 9600 or BaudRate > 115200 or BaudRate % 9600 != 0: raise ValueError('The given baudrate is invalid!')
        if address < MIN_ADDRESS or address > MAX_ADDRESS: raise ValueError('The given address is invalid!')
        if password < MIN_ADDRESS or password > MAX_ADDRESS: raise ValueError('The given password is invalid!')

        self._address = address
        self._password = password
        self.__call__(Serial)
    def __call__(self, ser: serial.Serial):
        self._serial = ser
        return self
    def __enter__(self):
        if not self.verifyPassword():
            raise ValueError('The given fingerprint sensor password is wrong!')

        self.UpdateSensorSettings()
        return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.Close()
    def __del__(self): self.Close()
    def Close(self):
        """ Close connection if still established """
        if self._serial is not None and self._serial.isOpen(): self._serial.close()
        self._sensor_settings = None

    @staticmethod
    def DefaultSerialSettings() -> dict: return PyFingerPrint._DefaultSerialSettings.copy()
    @property
    def Serial(self): return self._serial

    @staticmethod
    def __rightShift(n: int or bytes, x: int or bytes) -> int:
        """
        Performs a right-shift.

        Arguments:
            n (int or bytes): The number
            x (int or bytes): The amount of bits to shift

        Returns:
            The shifted number (int)
        """

        return n >> x & 0xFF
    @staticmethod
    def __leftShift(n: int or bytes, x: int or bytes) -> int:
        """
        Performs a left-shift.

        Arguments:
            n (int or bytes): The number
            x (int or bytes): The amount of bits to shift

        Returns:
            The shifted number (int)
        """

        return n << x
    @staticmethod
    def __bitAtPosition(n: int or bytes, p: int or bytes) -> int:
        """
        Gets the bit at the specified position.

        Arguments:
            n (int or bytes): The number
            p (int or bytes): The position

        Returns:
            The bit number (int)
        """

        ## A bitshift 2 ^ p
        twoP = 1 << p

        ## Binary AND composition (on both positions must be a 1)
        ## This can only happen at position p
        result = n & twoP
        return int(result > 0)
    @staticmethod
    def __byteToString(byte: bytes or str) -> bytes:
        """
        Converts a byte to string.

        Arguments:
            byte (int or bytes): The byte

        Returns:
            The string (str)
        """

        return struct.pack('@B', byte)
    @staticmethod
    def __stringToByte(string: str or bytes) -> bytes:
        """
        Convert one "string" byte (like '0xFF') to real integer byte (0xFF).

        Arguments:
            string (str or bytes): The string

        Returns:
            The byte (int)
        """

        return struct.unpack('@B', string)[0]

    def __writePacket(self, packetType: int, packetPayload: tuple or list):
        """
        Sends a packet to the sensor.

        Arguments:
            packetType (int): The packet type (either `COMMANDPACKET`, `DATAPACKET` or `ENDDATAPACKET`)
            packetPayload (tuple or list): The payload
        """

        ## Write header (one byte at once)
        self._serial.write(self.__byteToString(self.__rightShift(START_CODE, 8)))
        self._serial.write(self.__byteToString(self.__rightShift(START_CODE, 0)))

        self._serial.write(self.__byteToString(self.__rightShift(self._address, 24)))
        self._serial.write(self.__byteToString(self.__rightShift(self._address, 16)))
        self._serial.write(self.__byteToString(self.__rightShift(self._address, 8)))
        self._serial.write(self.__byteToString(self.__rightShift(self._address, 0)))

        self._serial.write(self.__byteToString(packetType))

        ## The packet length = package payload (n bytes) + checksum (2 bytes)
        packetLength = len(packetPayload) + 2

        self._serial.write(self.__byteToString(self.__rightShift(packetLength, 8)))
        self._serial.write(self.__byteToString(self.__rightShift(packetLength, 0)))

        ## The packet checksum = packet type (1 byte) + packet length (2 bytes) + payload (n bytes)
        packetChecksum = packetType + self.__rightShift(packetLength, 8) + self.__rightShift(packetLength, 0)

        ## Write payload
        for i in range(0, len(packetPayload)):
            self._serial.write(self.__byteToString(packetPayload[i]))
            packetChecksum += packetPayload[i]

        ## Write checksum (2 bytes)
        self._serial.write(self.__byteToString(self.__rightShift(packetChecksum, 8)))
        self._serial.write(self.__byteToString(self.__rightShift(packetChecksum, 0)))
    def __readPacket(self) -> Tuple[Any, List[bytes or int]]:
        """
        Receives a packet from the sensor.

        Returns:
            A tuple that contain the following information:
            0: integer(1 byte) The packet type.
            1: integer(n bytes) The packet payload.

        Raises:
            Exception: if checksum is wrong
        """

        receivedPacketData = []
        i = 0

        while True:
            ## Ready one byte
            receivedFragment = self._serial.read()

            if len(receivedFragment) != 0:
                receivedFragment = self.__stringToByte(receivedFragment)
                ## print 'Received packet fragment = ' + hex(receivedFragment)
            else:
                continue

            ## Insert byte if packet seems valid
            receivedPacketData.insert(i, receivedFragment)
            i += 1

            ## Packet could be complete (the minimal packet size is 12 bytes)
            if i >= 12:
                ## Check the packet header
                if receivedPacketData[0] != self.__rightShift(START_CODE, 8) or receivedPacketData[1] != self.__rightShift(START_CODE, 0):
                    raise Exception('The received packet do not begin with a valid header!')

                ## Calculate packet payload length (combine the 2 length bytes)
                packetPayloadLength = self.__leftShift(receivedPacketData[7], 8)
                packetPayloadLength = packetPayloadLength | self.__leftShift(receivedPacketData[8], 0)

                ## Check if the packet is still fully received
                ## Condition: index counter < packet payload length + packet NumPadFrame
                if i < packetPayloadLength + 9:
                    continue

                ## At this point the packet should be fully received

                packetType = receivedPacketData[6]

                ## Calculate checksum:
                ## checksum = packet type (1 byte) + packet length (2 bytes) + packet payload (n bytes)
                packetChecksum = packetType + receivedPacketData[7] + receivedPacketData[8]

                packetPayload = []

                ## Collect package payload (ignore the last 2 checksum bytes)
                for j in range(9, 9 + packetPayloadLength - 2):
                    packetPayload.append(receivedPacketData[j])
                    packetChecksum += receivedPacketData[j]

                ## Calculate full checksum of the 2 separate checksum bytes
                receivedChecksum = self.__leftShift(receivedPacketData[i - 2], 8)
                receivedChecksum = receivedChecksum | self.__leftShift(receivedPacketData[i - 1], 0)

                if receivedChecksum != packetChecksum:
                    raise Exception('The received packet is corrupted (the checksum is wrong)!')

                return packetType, packetPayload

    def verifyPassword(self) -> bool:
        """
        Verifies password of the sensor.

        Returns:
            True if password is correct or False otherwise.

        Raises:
            Exception: if an error occured
        """

        packetPayload = (
                VERIFY_PASSWORD,
                self.__rightShift(self._password, 24),
                self.__rightShift(self._password, 16),
                self.__rightShift(self._password, 8),
                self.__rightShift(self._password, 0),
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Sensor password is correct
        if receivedPacketPayload[0] == OK:
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif receivedPacketPayload[0] == ADDR_CODE:
            raise Exception('The address is wrong')

        ## DEBUG: Sensor password is wrong
        elif receivedPacketPayload[0] == ERROR_WRONG_PASSWORD:
            return False

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def setPassword(self, newPassword) -> bool:
        """
        Sets the password of the sensor.

        Arguments:
            newPassword (int): The new password to use.

        Returns:
            True if password was set correctly or False otherwise.

        Raises:
            Exception: if an error occured
        """

        ## Validate the password (maximum 4 bytes)
        if newPassword < MIN_ADDRESS or newPassword > MAX_ADDRESS:
            raise ValueError('The given password is invalid!')

        packetPayload = (
                SET_PASSWORD,
                self.__rightShift(newPassword, 24),
                self.__rightShift(newPassword, 16),
                self.__rightShift(newPassword, 8),
                self.__rightShift(newPassword, 0),
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Password set was successful
        if receivedPacketPayload[0] == OK:
            self._password = newPassword
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))

    def setAddress(self, newAddress) -> bool:
        """
        Sets the sensor address.

        Arguments:
            newAddress (int): The new address to use.

        Returns:
            True if address was set correctly or False otherwise.

        Raises:
            Exception: if any error occurs
        """

        ## Validate the address (maximum 4 bytes)
        if newAddress < MIN_ADDRESS or newAddress > MAX_ADDRESS:
            raise ValueError('The given address is invalid!')

        packetPayload = (
                SET_ADDRESS,
                self.__rightShift(newAddress, 24),
                self.__rightShift(newAddress, 16),
                self.__rightShift(newAddress, 8),
                self.__rightShift(newAddress, 0),
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Address set was successful
        if receivedPacketPayload[0] == OK:
            self._address = newAddress
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))

    def setBaudRate(self, baudRate: int) -> bool:
        """
        Sets the baud rate.

        Arguments:
            baudRate (int): The baud rate

        Raises:
            ValueError: if passed baud rate is no multiple of 9600
            Exception: if any error occurs
        """

        if baudRate % 9600 != 0:
            raise ValueError("Invalid baud rate")

        return self.setSystemParameter(SET_SYSTEM_PARAMETER_BAUDRATE, baudRate // 9600)
    def getBaudRate(self) -> int:
        """
        Gets the baud rate.

        Returns:
            The baud rate (int).

        Raises:
            Exception: if any error occurs
        """

        if self._sensor_settings is None: self.UpdateSensorSettings()
        return self._sensor_settings.baudRate * 9600
        # return self.getSystemParameters()[6] * 9600

    def setSecurityLevel(self, securityLevel) -> bool:
        """
        Sets the security level of the sensor.

        Arguments:
            securityLevel (int): Value between 1 and 5 where 1 is lowest and 5 highest.

        Raises:
            Exception: if any error occurs
        """

        return self.setSystemParameter(SET_SYSTEM_PARAMETER_SECURITY_LEVEL, securityLevel)
    def setMaxPacketSize(self, packetSize):
        """
        Sets the maximum packet size of sensor.

        Arguments:
            packetSize (int): 32, 64, 128 and 256 are supported.

        Raises:
            ValueError: if passed packet size is invalid
            Exception: if any error occurs
        """

        try:
            packetSizes = { 32: 0, 64: 1, 128: 2, 256: 3 }
            packetMaxSizeType = packetSizes[packetSize]

        except KeyError:
            raise ValueError("Invalid packet size")

        self.setSystemParameter(SET_SYSTEM_PARAMETER_PACKAGE_SIZE, packetMaxSizeType)
    def getMaxPacketSize(self) -> Union[int, List[int]]:
        """
        Gets the maximum allowed size of a single packet.

        Returns:
            Return the max size (int).

        Raises:
            ValueError: if packet size is invalid
            Exception: if any error occurs
        """

        if self._sensor_settings is None: self.UpdateSensorSettings()
        packetMaxSizeType = self._sensor_settings.packetLength

        try:
            packetSizes = [32, 64, 128, 256]
            packetSize = packetSizes[packetMaxSizeType]

        except KeyError:
            raise ValueError("Invalid packet size")

        return packetSize

    def UpdateSensorSettings(self):
        self._sensor_settings = SystemParameters(self.getSystemParameters())
    def setSystemParameter(self, parameterNumber: int, parameterValue: int) -> bool:
        """
        Set a system parameter of the sensor.

        Arguments:
            parameterNumber (int): The parameter number. Use one of `SETSYSTEMPARAMETER_*` constants.
            parameterValue (int): The value

        Returns:
            True if successful or False otherwise.

        Raises:
            ValueError: if any passed parameter is invalid
            Exception: if any error occurs
        """

        ## Validate the baud rate parameter
        if parameterNumber == SET_SYSTEM_PARAMETER_BAUDRATE:
            if parameterValue < 1 or parameterValue > 12:
                raise ValueError('The given baud rate parameter is invalid!')

        ## Validate the security level parameter
        elif parameterNumber == SET_SYSTEM_PARAMETER_SECURITY_LEVEL:
            if parameterValue < 1 or parameterValue > 5:
                raise ValueError('The given security level parameter is invalid!')

        ## Validate the package length parameter
        elif parameterNumber == SET_SYSTEM_PARAMETER_PACKAGE_SIZE:
            if parameterValue < 0 or parameterValue > 3:
                raise ValueError('The given package length parameter is invalid!')

        ## The parameter number is not valid
        else:
            raise ValueError('The given parameter number is invalid!')

        packetPayload = (
                SET_SYSTEM_PARAMETER,
                parameterNumber,
                parameterValue,
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Parameter set was successful
        if receivedPacketPayload[0] == OK:
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif receivedPacketPayload[0] == ERROR_INVALID_REGISTER:
            raise Exception('Invalid register number')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def getSystemParameters(self) -> Tuple[int, int, int, int, Union[int, Any], int, int]:
        """
        Gets all available system information of the sensor.

        Returns:
            A tuple that contains the following information:
            0: integer(2 bytes) The status register.
            1: integer(2 bytes) The system ID.
            2: integer(2 bytes) The storage capacity.
            3: integer(2 bytes) The security level.
            4: integer(4 bytes) The sensor address.
            5: integer(2 bytes) The packet length.
            6: integer(2 bytes) The baud rate.

        Raises:
            Exception: if any error occurs
        """

        packetPayload = (GET_SYSTEM_PARAMETERS,)

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Ready successfully
        if receivedPacketPayload[0] == OK:
            statusRegister = self.__leftShift(receivedPacketPayload[1], 8) | self.__leftShift(receivedPacketPayload[2], 0)
            systemID = self.__leftShift(receivedPacketPayload[3], 8) | self.__leftShift(receivedPacketPayload[4], 0)
            storageCapacity = self.__leftShift(receivedPacketPayload[5], 8) | self.__leftShift(receivedPacketPayload[6], 0)
            securityLevel = self.__leftShift(receivedPacketPayload[7], 8) | self.__leftShift(receivedPacketPayload[8], 0)
            deviceAddress = ((receivedPacketPayload[9] << 8 | receivedPacketPayload[10]) << 8 | receivedPacketPayload[11]) << 8 | receivedPacketPayload[12]  ## TODO
            packetLength = self.__leftShift(receivedPacketPayload[13], 8) | self.__leftShift(receivedPacketPayload[14], 0)
            baudRate = self.__leftShift(receivedPacketPayload[15], 8) | self.__leftShift(receivedPacketPayload[16], 0)

            return statusRegister, systemID, storageCapacity, securityLevel, deviceAddress, packetLength, baudRate

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))

    def getStorageCapacity(self):
        """
        Gets the sensor storage capacity.

        Returns:
            The storage capacity (int).

        Raises:
            Exception: if any error occurs
        """

        if self._sensor_settings is None: self.UpdateSensorSettings()
        return self._sensor_settings.storageCapacity
        # return self.getSystemParameters()[2]
    @property
    def Capacity(self):
        if self._sensor_settings is None: self.UpdateSensorSettings()
        return self._sensor_settings.storageCapacity

    def getSecurityLevel(self):
        """
        Gets the security level of the sensor.

        Returns:
            The security level (int).

        Raises:
            Exception: if any error occurs
        """

        if self._sensor_settings is None: self.UpdateSensorSettings()
        return self._sensor_settings.securityLevel
        # return self.getSystemParameters()[3]



    def storeTemplate(self, positionNumber=-1, *, charBufferNumber=CHAR_BUFFER1) -> int:
        """
        Stores a template from the specified char buffer at the given position.

        Arguments:
            positionNumber (int): The position
            charBufferNumber (int): The char buffer. Use `CHARBUFFER1` or `CHARBUFFER2`.

        Returns:
            The position number (int) of the stored template.

        Raises:
            ValueError: if passed position or char buffer is invalid
            Exception: if any error occurs
        """

        ## Find a free index
        if positionNumber == -1:
            for page in range(0, 4):
                ## Free index found?
                if positionNumber >= 0:
                    break

                templateIndex = self.getTemplateIndex(page)

                for i in range(0, len(templateIndex)):
                    if not templateIndex[i]:  ## PageIndex not used?
                        positionNumber = (len(templateIndex) * page) + i
                        break

        if positionNumber < 0 or positionNumber >= self.getStorageCapacity():
            raise ValueError('The given position number is invalid!')

        if charBufferNumber != CHAR_BUFFER1 and charBufferNumber != CHAR_BUFFER2:
            raise ValueError('The given char buffer number is invalid!')

        packetPayload = (
                STORE_TEMPLATE,
                charBufferNumber,
                self.__rightShift(positionNumber, 8),
                self.__rightShift(positionNumber, 0),
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Template stored successful
        if receivedPacketPayload[0] == OK:
            return positionNumber

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif receivedPacketPayload[0] == ERROR_INVALID_POSITION:
            raise Exception('Could not store template in that position')

        elif receivedPacketPayload[0] == ERROR_FLASH:
            raise Exception('error writing to flash')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def searchTemplate(self, charBufferNumber=CHAR_BUFFER1, positionStart=0, count=-1) -> Result:
        """
        Searches inside the database for the characteristics in char buffer.

        Arguments:
            charBufferNumber (int): The char buffer. Use `CHARBUFFER1` or `CHARBUFFER2`.
            positionStart (int): The position to start the search
            count (int): The number of templates

        Returns:
            A tuple that contain the following information:
            0: integer(2 bytes) The position number of found template.
            1: integer(2 bytes) The accuracy score of found template.

        Raises:
            Exception: if any error occurs
        """

        if charBufferNumber != CHAR_BUFFER1 and charBufferNumber != CHAR_BUFFER2:
            raise ValueError('The given charbuffer number is invalid!')

        if count > 0:
            templatesCount = count
        else:
            templatesCount = self.getStorageCapacity()

        packetPayload = (
                SEARCH_TEMPLATE,
                charBufferNumber,
                self.__rightShift(positionStart, 8),
                self.__rightShift(positionStart, 0),
                self.__rightShift(templatesCount, 8),
                self.__rightShift(templatesCount, 0),
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Found template
        if receivedPacketPayload[0] == OK:
            positionNumber = self.__leftShift(receivedPacketPayload[1], 8)
            positionNumber = positionNumber | self.__leftShift(receivedPacketPayload[2], 0)

            accuracyScore = self.__leftShift(receivedPacketPayload[3], 8)
            accuracyScore = accuracyScore | self.__leftShift(receivedPacketPayload[4], 0)

            return Result(True, positionNumber, accuracyScore)

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: Did not found a matching template
        elif receivedPacketPayload[0] == ERROR_NO_TEMPLATE_FOUND:
            return Result(False, -1, -1)

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def loadTemplate(self, positionNumber, *, charBufferNumber=CHAR_BUFFER1) -> bool:
        """
        Loads an existing template specified by position number to specified char buffer.

        Arguments:
            positionNumber (int): The position
            charBufferNumber (int): The char buffer. Use `CHARBUFFER1` or `CHARBUFFER2`.

        Returns:
            True if successful or False otherwise.

        Raises:
            ValueError: if passed position or char buffer is invalid
            Exception: if any error occurs
        """

        if positionNumber < 0 or positionNumber >= self.getStorageCapacity():
            raise ValueError('The given position number is invalid!')

        if charBufferNumber != CHAR_BUFFER1 and charBufferNumber != CHAR_BUFFER2:
            raise ValueError('The given char buffer number is invalid!')

        packetPayload = (
                LOAD_TEMPLATE,
                charBufferNumber,
                self.__rightShift(positionNumber, 8),
                self.__rightShift(positionNumber, 0),
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Template loaded successful
        if receivedPacketPayload[0] == OK:
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif receivedPacketPayload[0] == ERROR_LOAD_TEMPLATE:
            raise Exception('The template could not be read')

        elif receivedPacketPayload[0] == ERROR_INVALID_POSITION:
            raise Exception('Could not load template from that position')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def deleteTemplate(self, positionNumber, count=1) -> bool:
        """
        Deletes templates from fingerprint database. Per default one.

        Arguments:
            positionNumber (int): The position
            count (int): The number of templates to be deleted.

        Returns:
            True if successful or False otherwise.

        Raises:
            ValueError: if passed position or count is invalid
            Exception: if any error occurs
        """

        capacity = self.getStorageCapacity()

        if positionNumber < 0 or positionNumber >= capacity:
            raise ValueError('The given position number is invalid!')

        if count < 0 or count > capacity - positionNumber:
            raise ValueError('The given count is invalid!')

        packetPayload = (
                DELETE_TEMPLATE,
                self.__rightShift(positionNumber, 8),
                self.__rightShift(positionNumber, 0),
                self.__rightShift(count, 8),
                self.__rightShift(count, 0),
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Template deleted successful
        if receivedPacketPayload[0] == OK:
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif receivedPacketPayload[0] == ERROR_INVALID_POSITION:
            raise Exception('Invalid position')

        ## DEBUG: Could not delete template
        elif receivedPacketPayload[0] == ERROR_DELETE_TEMPLATE:
            return False

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def getTemplateIndex(self, page) -> List[bool]:
        """
        Gets a list of the template positions with usage indicator.

        Arguments:
            page (int): The page (value between 0 and 3).

        Returns:
            The list.

        Raises:
            ValueError: if passed page is invalid
            Exception: if any error occurs
        """

        if page < 0 or page > 3:
            raise ValueError('The given index page is invalid!')

        packetPayload = (
                TEMPLATE_INDEX,
                page,
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Ready index table successfully
        if receivedPacketPayload[0] == OK:
            templateIndex = []

            ## Contain the table page bytes (skip the first status byte)
            pageElements = receivedPacketPayload[1:]

            for pageElement in pageElements:
                ## Text every bit (bit = template position is used indicator) of a table page element
                for p in range(0, 7 + 1):
                    positionIsUsed = (self.__bitAtPosition(pageElement, p) == 1)
                    templateIndex.append(positionIsUsed)

            return templateIndex

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def getTemplateCount(self) -> int:
        """
        Gets the number of stored templates.

        Returns:
            The template count (int).

        Raises:
            Exception: if any error occurs
        """

        packetPayload = (
                TEMPLATE_COUNT,
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Ready successfully
        if receivedPacketPayload[0] == OK:
            templateCount = self.__leftShift(receivedPacketPayload[1], 8)
            templateCount = templateCount | self.__leftShift(receivedPacketPayload[2], 0)
            return templateCount

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def createTemplate(self) -> bool:
        """
        Combines the characteristics which are stored in char buffer 1 and char buffer 2 into one template.
        The created template will be stored again in char buffer 1 and char buffer 2 as the same.

        Returns:
            True if successful or False otherwise.

        Raises:
            Exception: if any error occurs
        """

        packetPayload = (
                CREATE_TEMPLATE,
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Template created successful
        if receivedPacketPayload[0] == OK:
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: The characteristics not matching
        elif receivedPacketPayload[0] == ERROR_CHARACTERISTICS_MISMATCH:
            return False

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    @property
    def Size(self): return self.getTemplateCount()


    def generateRandomNumber(self) -> int:
        """
        Generates a random 32-bit decimal number.

        Author:
            Philipp Meisberger <team@pm-codeworks.de>

        Returns:
            The generated random number (int).

        Raises:
            Exception: if any error occurs
        """
        packetPayload = (
                GENERATE_RANDOM_NUMBER,
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        if receivedPacketPayload[0] == OK:
            pass

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))

        number = 0
        number = number | self.__leftShift(receivedPacketPayload[1], 24)
        number = number | self.__leftShift(receivedPacketPayload[2], 16)
        number = number | self.__leftShift(receivedPacketPayload[3], 8)
        number = number | self.__leftShift(receivedPacketPayload[4], 0)
        return number
    ## TODO: Implementation of uploadImage()

    def downloadImage(self, imageDestination):
        """
        Downloads the image from image buffer.

        Arguments:
            imageDestination (str): Path to image

        Raises:
            ValueError: if directory is not writable
            Exception: if any error occurs
        """

        destinationDirectory = os.path.dirname(imageDestination)

        if os.access(destinationDirectory, os.W_OK) == False:
            raise ValueError('The given destination directory "' + destinationDirectory + '" is not writable!')

        packetPayload = (
                DOWNLOAD_IMAGE,
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)

        ## Get first reply packet
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: The sensor will sent follow-up packets
        if receivedPacketPayload[0] == OK:
            pass

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif receivedPacketPayload[0] == ERROR_DOWNLOAD_IMAGE:
            raise Exception('Could not download image')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))

        data = []

        ## Get follow-up data packets until the last data packet is received
        while receivedPacketType != END_DATA_PACKET:
            receivedPacket = self.__readPacket()

            receivedPacketType = receivedPacket[0]
            receivedPacketPayload = receivedPacket[1]

            if receivedPacketType != DATA_PACKET and receivedPacketType != END_DATA_PACKET:
                raise Exception('The received packet is no data packet!')

            data.append(receivedPacketPayload)

        ## Initialize image
        resultImage = Image.new('L', (256, 288), 'white')
        pixels = resultImage.load()
        (resultImageWidth, resultImageHeight) = resultImage.size
        row = 0
        column = 0

        for y in range(resultImageHeight):
            for x in range(resultImageWidth):
                ## One byte contains two pixels
                ## Thanks to Danylo Esterman <soundcracker@gmail.com> for the "multiple with 17" improvement:
                if x % 2 == 0:
                    ## Draw left 4 Bits one byte of package
                    pixels[x, y] = (data[row][column] >> 4) * 17
                else:
                    ## Draw right 4 Bits one byte of package
                    pixels[x, y] = (data[row][column] & 0x0F) * 17
                    column += 1

                    ## Reset
                    if column == len(data[row]):
                        row += 1
                        column = 0

        resultImage.Save(imageDestination)
    def convertImage(self, charBufferNumber=CHAR_BUFFER1) -> bool:
        """
        Converts the image in image buffer to characteristics and stores it in specified char buffer.

        Arguments:
            charBufferNumber (int): The char buffer. Use `CHARBUFFER1` or `CHARBUFFER2`.

        Returns:
            True if successful or False otherwise.

        Raises:
            ValueError: if passed char buffer is invalid
            Exception: if any error occurs
        """

        if charBufferNumber != CHAR_BUFFER1 and charBufferNumber != CHAR_BUFFER2:
            raise ValueError('The given char buffer number is invalid!')

        packetPayload = (
                CONVERT_IMAGE,
                charBufferNumber,
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Image converted
        if receivedPacketPayload[0] == OK:
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif receivedPacketPayload[0] == ERROR_MESSY_IMAGE:
            raise Exception('The image is too messy')

        elif receivedPacketPayload[0] == ERROR_FEW_FEATURE_POINTS:
            raise Exception('The image contains too few feature points')

        elif receivedPacketPayload[0] == ERROR_INVALID_IMAGE:
            raise Exception('The image is invalid')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def readImage(self):
        """
        Reads the image of a finger and stores it in image buffer.

        Returns:
            True if image was read successfully or False otherwise.

        Raises:
            Exception: if any error occurs
        """

        packetPayload = (
                READ_IMAGE,
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Image read successful
        if receivedPacketPayload[0] == OK:
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: No finger found
        elif receivedPacketPayload[0] == ERROR_NO_FINGER:
            return False

        elif receivedPacketPayload[0] == ERROR_READ_IMAGE:
            raise Exception('Could not read image')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))


    def compareCharacteristics(self) -> int:
        """
        Compare the finger characteristics of char buffer 1 with char buffer 2 and returns the accuracy score.

        Returns:
            The accuracy score (int). 0 means fingers are not the same.

        Raises:
            Exception: if any error occurs
        """

        packetPayload = (COMPARE_CHARACTERISTICS,)

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Comparison successful
        if receivedPacketPayload[0] == OK:
            accuracyScore = self.__leftShift(receivedPacketPayload[1], 8)
            accuracyScore = accuracyScore | self.__leftShift(receivedPacketPayload[2], 0)
            return accuracyScore

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: The characteristics do not matching
        elif receivedPacketPayload[0] == ERROR_NO_TMATCHING:
            return 0

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))
    def uploadCharacteristics(self, characteristicsData: List[int], *, charBufferNumber=CHAR_BUFFER1) -> bool:
        """
        Uploads finger characteristics to specified char buffer.

        Author:
            David Gilson <davgilson@live.fr>

        Arguments:
            charBufferNumber (int): The char buffer. Use `CHARBUFFER1` or `CHARBUFFER2`.
            characteristicsData (list): The characteristics

        Returns:
            True if everything is right.

        Raises:
            ValueError: if passed char buffer or characteristics are invalid
            Exception: if any error occurs
        """

        if charBufferNumber != CHAR_BUFFER1 and charBufferNumber != CHAR_BUFFER2: raise ValueError('The given char buffer number is invalid!')

        if not characteristicsData: raise ValueError('The characteristics data is required!')
        if not isinstance(characteristicsData, list) or not all(isinstance(c, int) for c in characteristicsData): raise TypeError(f'Expected List[int] got {type(characteristicsData)}')

        maxPacketSize = self.getMaxPacketSize()

        ## Upload command
        packetPayload = (UPLOAD_CHARACTERISTICS, charBufferNumber)

        self.__writePacket(COMMAND_PACKET, packetPayload)

        ## Get first reply packet
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: The sensor will sent follow-up packets
        if receivedPacketPayload[0] == OK:
            pass

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif receivedPacketPayload[0] == PACKET_RESPONSE_FAIL:
            raise Exception('Could not upload characteristics')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))

        ## Upload data packets
        packetNumber = int(len(characteristicsData) / maxPacketSize)

        if packetNumber <= 1:
            self.__writePacket(END_DATA_PACKET, characteristicsData)
        else:
            i = 1
            while i < packetNumber:
                lfrom = (i - 1) * maxPacketSize
                lto = lfrom + maxPacketSize
                self.__writePacket(DATA_PACKET, characteristicsData[lfrom:lto])
                i += 1

            lfrom = (i - 1) * maxPacketSize
            lto = len(characteristicsData)
            self.__writePacket(END_DATA_PACKET, characteristicsData[lfrom:lto])

        ## Verify uploaded characteristics
        characterics = self.downloadCharacteristics(charBufferNumber=charBufferNumber)
        return characterics == characteristicsData
    def downloadCharacteristics(self, *, charBufferNumber=CHAR_BUFFER1) -> list:
        """
        Downloads the finger characteristics from the specified char buffer.

        Arguments:
            charBufferNumber (int): The char buffer. Use `CHARBUFFER1` or `CHARBUFFER2`.

        Returns:
            The characteristics (list).

        Raises:
            ValueError: if passed char buffer is invalid
            Exception: if any error occurs
        """

        if charBufferNumber != CHAR_BUFFER1 and charBufferNumber != CHAR_BUFFER2:
            raise ValueError('The given char buffer number is invalid!')

        packetPayload = (DOWNLOAD_CHARACTERISTICS, charBufferNumber)

        self.__writePacket(COMMAND_PACKET, packetPayload)

        ## Get first reply packet
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: The sensor will sent follow-up packets
        if receivedPacketPayload[0] == OK:
            pass

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        elif receivedPacketPayload[0] == ERROR_DOWNLOAD_CHARACTERISTICS:
            raise Exception('Could not download characteristics')

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))

        completePayload = []

        ## Get follow-up data packets until the last data packet is received
        while receivedPacketType != END_DATA_PACKET:
            receivedPacket = self.__readPacket()

            receivedPacketType = receivedPacket[0]
            receivedPacketPayload = receivedPacket[1]

            if receivedPacketType != DATA_PACKET and receivedPacketType != END_DATA_PACKET:
                raise Exception('The received packet is no data packet!')

            for i in range(0, len(receivedPacketPayload)):
                completePayload.append(receivedPacketPayload[i])

        return completePayload

    def UploadDataBase(self, db: Union[Dict[int, Union[List[int], Record]], Union[List[int], Record]]):
        if isinstance(db, dict): db = list(db.values())
        assert (isinstance(db, list))

        if not self.ClearDatabase(): raise ValueError('ClearDatabase Failed')
        if len(db) >= self.Capacity: raise ValueError('Too Many Records for this device')

        for i, chars in enumerate(db): self.SetRecord(i, chars)
    def DownloadDataBase(self) -> List[Record]:
        d: List[Record] = []

        for i in range(self.Size):
            d.append(self.GetRecord(i))

        return d
    def ClearDatabase(self) -> bool:
        """
        Deletes all templates from the fingeprint database.

        Returns:
            True if successful or False otherwise.

        Raises:
            Exception: if any error occurs
        """

        packetPayload = (
                CLEAR_DATABASE,
                )

        self.__writePacket(COMMAND_PACKET, packetPayload)
        receivedPacket = self.__readPacket()

        receivedPacketType = receivedPacket[0]
        receivedPacketPayload = receivedPacket[1]

        if receivedPacketType != ACK_PACKET:
            raise Exception('The received packet is no ack packet!')

        ## DEBUG: Database cleared successful
        if receivedPacketPayload[0] == OK:
            return True

        elif receivedPacketPayload[0] == ERROR_COMMUNICATION:
            raise Exception('Communication error')

        ## DEBUG: Could not Clear database
        elif receivedPacketPayload[0] == ERROR_CLEAR_DATABASE:
            return False

        else:
            raise Exception('Unknown error ' + hex(receivedPacketPayload[0]))

    def SetRecord(self, position_number: int, chars: Union[List[int], Record]) -> int:
        if isinstance(chars, Record): chars = chars.characteristics
        if self.uploadCharacteristics(chars): return self.storeTemplate(position_number)
    def GetRecord(self, position_number: int, *, charBufferNumber: int = CHAR_BUFFER1) -> Record:
        """
            returns a list of the HASH and the fingerprint Characteristics.
        :param position_number:
        :param charBufferNumber:
        :return: [position_number, hashed, characteristics]
        """
        self.loadTemplate(position_number, charBufferNumber=charBufferNumber)  # Downloads the characteristics of template loaded in char buffer 1
        characteristics = self.downloadCharacteristics(charBufferNumber=charBufferNumber)  # Downloads the characteristics of template loaded in char buffer 1
        hashed = hashlib.sha256(str(characteristics).encode()).hexdigest()  # Hashes characteristics of template
        return Record(position_number, hashed, characteristics)

    def ScanFinger(self, MinimumAccuracyScore: int, Timeout: Union[int, Event] = None, *, charBufferNumber: int = CHAR_BUFFER1) -> Result:
        self._doReadImage(Timeout)
        self.convertImage(charBufferNumber)
        result = self.searchTemplate()
        if result.Success and result.AccuracyScore >= MinimumAccuracyScore: return result

        return Result(False, -1, -1)
    def ScanFingerVerify(self, Timeout: Union[int, Event] = None, *, charBufferNumber: int = CHAR_BUFFER1) -> Result:
        self._doReadImage(Timeout)
        self.convertImage(charBufferNumber)
        return self.searchTemplate()

    def _doReadImage(self, Timeout: Union[int, Event] = None) -> (int, int or float):
        if Timeout is None: pass
        elif isinstance(Timeout, Event): pass
        elif isinstance(Timeout, int):
            if Timeout < 0: raise ValueError(f'Provided Timeout is an invalid value. [ {Timeout} ]')
        else:  raise TypeError(f'Provided Timeout is an invalid Type: expected Union[int, Event], got {type(Timeout)}')

        start = time.time()
        while not self.readImage():
            if isinstance(Timeout, Event) and Timeout.is_set(): break
            elif isinstance(Timeout, int) and time.time() - start > Timeout: break



    def reset_input_buffer(self): self._serial.reset_input_buffer()

    def _ThrowIfSerialIsNone(self):
        if self._serial is None:
            raise serial.SerialException('Serial Port not active. must use Context ProcessManager and/or pass in a serial object')

    @staticmethod
    def ClearAndSync(conm: Connection, *, endMessage=None):
        """
            Clear a multiprocessing.connection.Connection buffer to sync both ends.

        :param endMessage: Optional Message to send after sync is done.
        :type endMessage: any pickable object
        :param conm: the connection / pipe
        :type conm: multiprocessing.connection.Connection
        :return:
        :rtype:
        """
        while conm.poll():  # Clear buffers to sync both ends.
            _ = conm.recv()

        if endMessage: conm.send(endMessage)

    @staticmethod
    def ClearAndSyncUntilReady(conm: Connection, *, endMessage=None):
        """
            Clear a multiprocessing.connection.Connection buffer to sync both ends.

        :param endMessage: Optional Message to send after sync is done.
        :type endMessage: any pickable object
        :param conm: the connection / pipe
        :type conm: multiprocessing.connection.Connection
        :return:
        :rtype:
        """
        while conm.poll():  # Clear buffers to sync both ends.
            msg = conm.recv()
            if isinstance(msg, type(endMessage)) and msg == endMessage: break



def Test():
    print('__TestPyFingerprint__')
    # ser = serial.Serial(port=port, baudrate=57600)
    # with serial.Serial(port='com3', baudrate=57600) as ser:
    from TkinterExtensions import PlatformIsLinux
    with serial.Serial(port=default_port if PlatformIsLinux else 'com4', baudrate=PyFingerPrint.DefaultBaudRate) as ser:  # Serial=ser
        with PyFingerPrint(ser) as fpm:  # Serial=ser
            # f = PyFingerPrint(port=port)  # , Serial=ser)

            # Gets some sensor information
            # print('Currently used templates: ' + str(f.getTemplateCount()) + '/' + str(f.getStorageCapacity()))

            print(fpm.getSystemParameters())
            print('Waiting for finger...')

            while not fpm.readImage(): pass  # Wait that finger is read again
            fpm.convertImage()  # Converts read image to characteristics and stores It in char buffer 1

            result = fpm.searchTemplate()  # Checks if finger is already enrolled
            positionNumber = result.Position

            if positionNumber >= 0:
                print('Template already exists at position #' + str(positionNumber))

            print('Remove finger...')
            time.sleep(1)
            print('Waiting for same finger again...')

            while not fpm.readImage(): pass  # Wait that finger is read again
            fpm.convertImage(CHAR_BUFFER2)  # Converts read image to characteristics and stores It in char buffer 2

            if fpm.compareCharacteristics() == 0:  # Compares the charbuffers
                raise Exception('Fingers do not match')

            fpm.createTemplate()  # Creates a template
            positionNumber = fpm.storeTemplate()  # Saves template at new position number
            print('Finger enrolled successfully!')
            print('New template position #' + str(positionNumber))

            while not fpm.readImage(): pass
            fpm.convertImage()  # Converts read image to characteristics and stores It in char buffer 1
            result = fpm.searchTemplate()  # Searches template

            positionNumber = result.Position
            accuracyScore = result.AccuracyScore

            if positionNumber == -1:
                print('No match found!')
            else:
                print('Found template at position #' + str(positionNumber))
                print('The accuracy score is: ' + str(accuracyScore))

            print(fpm.GetRecord(positionNumber))
            # if f.deleteTemplate(positionNumber):
            #     print('Template deleted!')

            # imageDestination = tempfile.gettempdir() + '/fingerprint.bmp'
            # f.downloadImage(imageDestination)

            print('f.generateRandomNumber(): ', fpm.generateRandomNumber())


if __name__ == '__main__':
    Test()
