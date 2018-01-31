#!/usr/bin/env python

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#
#       DESCRIPTION: Having an example all in one file including miscancellous possibilites of the 
#		library and being able to call them from command line
#
#       CALL SAMPLE:
#               Usage  python2 fingerprint_reader_function.py -h will give you the possibilities
#
#       @author: Philippe Gachoud inspired from Bastian Raschke files and examples
#       @creation: 20180101
#       @last modification:
#       @version: 1.0
#       @URL: $URL
#
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

# INCLUDES
import sys
import logging 
import time
from pyfingerprint.pyfingerprint import PyFingerprint
import argparse
import hashlib

# CONSTANTS
DEFAULT_USB_DEVICE = '/dev/ttyUSB0' 

# VARIABLES
global f # Fingerprintreader
usb_device = DEFAULT_USB_DEVICE

# FUNCTIONS DEFINITION 
def init():
	global f
	logging.basicConfig(level=logging.DEBUG, stream=sys.stdout, filemode="a+", format="%(asctime)-15s %(levelname)-8s %(message)s")
	try:
	    f = PyFingerprint(usb_device, 57600, 0xFFFFFFFF, 0x00000000)

	    if ( f.verifyPassword() == False ):
		raise ValueError('The given fingerprint sensor password is wrong!')

	except Exception as e:
	    print('The fingerprint sensor could not be initialized!')
	    print('Exception message: ' + str(e))
	    exit(1)

def display_system_parameters():
	""" Display system parameters as logger info level"""
	system_parameters = f.getSystemParameters()
	logging.info("System parameters : status register (%s), system id(%s), storage capacity(%s), security level(%s), sensor address(%s), packet length(%s), baudrate(%s)" % (system_parameters[0], system_parameters[1], system_parameters[2], system_parameters[3], system_parameters[4], system_parameters[5], system_parameters[6]))

def delete():
	"""Deletes a template after asking for its position, first position is 0 """
	try:
		positionNumber = input('Please enter the template position you want to delete: ')
		positionNumber = int(positionNumber)

		if ( f.deleteTemplate(positionNumber) == True ):
			print('Template deleted!')
	except Exception as e:
		print('Operation failed!')
		print('Exception message: ' + str(e))
		exit(1)

def delete_all():
	"""Deletes all templates after asking for confirmation"""
	try:
		answer = raw_input('Do you really want to delete all templates? y/n:')

		if ( answer == "y" ):
			f.clearDatabase()
			print("Templates deleted! %s/%s" % (f.getTemplateCount(), f.getStorageCapacity()))
	except Exception as e:
		print('Operation failed!')
		print('Exception message: ' + str(e))
		exit(1)

def download_image():
	"""Downloads image of read fingerprint into temp directory"""
	try:
		print('Waiting for finger...')

		## Wait that finger is read
		while ( f.readImage() == False ):
			pass

		print('Downloading image (this take a while)...')

		imageDestination =  tempfile.gettempdir() + '/fingerprint.bmp'
		f.downloadImage(imageDestination)

		print('The image was saved to "' + imageDestination + '".')

	except Exception as e:
		print('Operation failed!')
		print('Exception message: ' + str(e))
		exit(1)

def search():
	"""Searches for given fingerprint"""
	## Tries to search the finger and calculate hash
	try:
		print('Waiting for finger...')

		## Wait that finger is read
		while ( f.readImage() == False ):
			pass

		## Converts read image to characteristics and stores it in charbuffer 1
		logging.debug("Image read converting it")
		f.convertImage(0x01)

		## Searchs template
		result = f.searchTemplate()

		positionNumber = result[0]
		accuracyScore = result[1]

		if ( positionNumber == -1 ):
			print('No match found!')
			exit(0)
		else:
			print('Found template at position #' + str(positionNumber))
			print('The accuracy score is: ' + str(accuracyScore))

		## OPTIONAL stuff
		##

		## Loads the found template to charbuffer 1
		f.loadTemplate(positionNumber, 0x01)

		## Downloads the characteristics of template loaded in charbuffer 1
		characteristics = str(f.downloadCharacteristics(0x01)).encode('utf-8')
		logging.debug("Characteristics raw:%s" % (characteristics))

		## Hashes characteristics of template
		print('SHA-2 hash of template: ' + hashlib.sha256(characteristics).hexdigest())

	except Exception as e:
		print('Operation failed!')
		print('Exception message: ' + str(e))
		exit(1)

def enroll():
	"""Asks for fingerprint and adds it to database"""
	try:
		print('Waiting for finger...')

		## Wait that finger is read
		while ( f.readImage() == False ):
			pass

		## Converts read image to characteristics and stores it in charbuffer 1
		logging.debug("Image read, converting it")
		f.convertImage(0x01)

		## Checks if finger is already enrolled
		result = f.searchTemplate()
		positionNumber = result[0]

		if ( positionNumber >= 0 ):
			print('Template already exists at position #' + str(positionNumber))
			exit(0)

		print('Remove finger...')
		time.sleep(2)

		print('Waiting for same finger again...')

		## Wait that finger is read again
		while ( f.readImage() == False ):
			pass

		## Converts read image to characteristics and stores it in charbuffer 2
		f.convertImage(0x02)

		## Compares the charbuffers
		if ( f.compareCharacteristics() == 0 ):
			raise Exception('Fingers do not match')

		## Creates a template
		f.createTemplate()

		## Saves template at new position number
		positionNumber = f.storeTemplate()
		print('Finger enrolled successfully!')
		print('New template position #' + str(positionNumber))

	except Exception as e:
		print('Operation failed!')
		print('Exception message: ' + str(e))
		exit(1)

def init_arg_parse():
	global parser, usb_device
	parser = argparse.ArgumentParser(description='Do the given action with fingerprint reader')
	
	parser.add_argument("-v", "--verbose", help="Display system parameters of sensor", action="store_true")
	parser.add_argument("-u", "--usb_device", help="Sets used usb_device which by default is /dev/ttyUSB0", action="store_true", type=str)
	parser.add_argument("-e", "--enroll", help="Create a new fingerprint model and store it into database", action="store_true")
	parser.add_argument("-t", "--templates", help="Display current templates count", action="store_true")
	parser.add_argument("-d", "--delete", help="Deletes a template after asking its position to user (first position is 0)", action="store_true")
	parser.add_argument("-D", "--delete_all_templates", help="Deletes all templates of database", action="store_true")
	parser.add_argument("-i", "--download_image", help="Downloads image and put it into tempDir", action="store_true")
	parser.add_argument("-s", "--search", help="Searches for given fingerprint into database and display if found", action="store_true")
	args = parser.parse_args()
	if args.verbose:
		display_system_parameters()
	elif args.usb_device:
		logging.debug("Changing interface to %s" % args.usb_device)
		usb_device = args.usb_device
	elif args.enroll:
		enroll()
	elif args.delete:
		delete()
	elif args.delete_all_templates:
		delete_all()
	elif args.download_image:
		download_image()
	elif args.search:
		search()
	elif args.templates:
		logging.info("Currently used templates %s/%s" % (f.getTemplateCount(), f.getStorageCapacity()))	
	else:
		parser.print_help()

	
def main():
	global f
	init_arg_parse()
	init()

main()
