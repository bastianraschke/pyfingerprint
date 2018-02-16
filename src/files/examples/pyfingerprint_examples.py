#!/usr/bin/env python
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#
#       DESCRIPTION: Examples of use of the pyfingerprint library
#
#       USAGE: pyfingerprint_example.py -h will give you the possibilities
#
#       @author: Philippe Gachoud inspired from Bastian Raschke files and examples
#       @creation: 20180101
#       @last modification:
#       @version: 1.0
#       @URL: fingerprint_reader/pyfingerprint/src/files/examples
#
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
TEMPLATES_PAGES_COUNT = 4

# VARIABLES
global f # Fingerprintreader
f = None
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
		logging.exception('The fingerprint sensor could not be initialized')
	    	raise

def display_system_parameters():
	""" Display system parameters as logger info level"""
	system_parameters = f.getSystemParameters()
	logging.info("System parameters : status register (%s), system id(%s), storage capacity(%s), security level(%s), sensor address(%s), packet length(%s), baudrate(%s)" % (system_parameters[0], system_parameters[1], system_parameters[2], system_parameters[3], system_parameters[4], system_parameters[5], system_parameters[6]))

def delete():
	"""Deletes a template after asking for its position, first position is 0 """
	try:
		position_number = input('Please enter the template position you want to delete: ')
		position_number = int(position_number)

		if ( f.deleteTemplate(position_number) == True ):
			print('Template deleted!')
	except Exception as e:
		logging.exception('Could not delete %s' % position_number)
		raise

def delete_all():
	"""Deletes all templates after asking for confirmation"""
	try:
		answer = raw_input('Do you really want to delete all templates? y/n:')

		if ( answer == "y" ):
			f.clearDatabase()
			print("Templates deleted! %s/%s" % (f.getTemplateCount(), f.getStorageCapacity()))
	except Exception as e:
		logging.exception('Could not delete all')
		raise

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
		logging.exception('Could not download image')
		raise

def search():
	"""Searches for given fingerprint"""
	## Tries to search the finger and calculate hash
	try:
		print('Waiting for finger...')
		raise RuntimeError('this is a test exception')

		## Wait that finger is read
		while ( f.readImage() == False ):
			pass

		## Converts read image to characteristics and stores it in charbuffer 1
		logging.debug("Image read converting it")
		f.convertImage(0x01)

		## Searchs template
		result = f.searchTemplate()

		position_number = result[0]
		accuracyScore = result[1]

		if ( position_number == -1 ):
			print('No match found!')
			exit(0)
		else:
			print('Found template at position #' + str(position_number))
			print('The accuracy score is: ' + str(accuracyScore))

		## OPTIONAL stuff
		##

		## Loads the found template to charbuffer 1
		f.loadTemplate(position_number, 0x01)

		## Downloads the characteristics of template loaded in charbuffer 1
		characteristics = str(f.downloadCharacteristics(0x01)).encode('utf-8')
		logging.debug("Characteristics raw:%s" % (characteristics))

		## Hashes characteristics of template
		print('SHA-2 hash of template: ' + hashlib.sha256(characteristics).hexdigest())

	except Exception as e:
		logging.exception('Could not display index table')
		raise	

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
		position_number = result[0]

		if ( position_number >= 0 ):
			print('Template already exists at position #' + str(position_number))
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
		position_number = f.storeTemplate()
		print('Finger enrolled successfully!')
		print('New template position #' + str(position_number))

	except Exception as e:
		logging.exception('Could not enroll your fingerprint')
		raise

def display_index_table():
	"""Displays the index tables of stored fingerprints"""
	try:
		logging.info('Currently used templates: %s/%s' % (f.getTemplateCount(), f.getStorageCapacity()))
		for page in range(0, 4):
			tableIndex = f.getTemplateIndex(page)
			s = "";
			for i in range(0, len(tableIndex)):
				s = s + "p.%s:index:%s:%s|" % (page, i, tableIndex[i])
			print(s)
	except Exception as e:
		logging.exception('Could not display index table')
		raise

def init_arg_parse():
	global parser, usb_device
	parser = argparse.ArgumentParser(description='Do the given action with fingerprint reader')
	
	parser.add_argument("-v", "--verbose", help="Display system parameters of sensor", action="store_true")
	parser.add_argument("-u", "--usb_device", type=str, help="Sets used usb_device which by default is /dev/ttyUSB0")
	parser.add_argument("-e", "--enroll", help="Create a new fingerprint model and store it into database", action="store_true")
	parser.add_argument("-t", "--templates", help="Display current templates count", action="store_true")
	parser.add_argument("-I", "--index_table", help="Display current index table (templates)", action="store_true")
	parser.add_argument("-d", "--delete", help="Deletes a template after asking its position to user (first position is 0)", action="store_true")
	parser.add_argument("-D", "--delete_all_templates", help="Deletes all templates of database", action="store_true")
	parser.add_argument("-i", "--download_image", help="Downloads image and put it into tempDir", action="store_true")
	parser.add_argument("-s", "--search", help="Searches for given fingerprint into database and display if found", action="store_true")
	args = parser.parse_args()
	if args.usb_device:
		logging.debug("Changing interface to %s" % args.usb_device)
		usb_device = args.usb_device
	if args.verbose:
		display_system_parameters()
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
	elif args.index_table:
		display_index_table()
	else:
		parser.print_help()

	
def main():
	global f
	init()
	init_arg_parse()

main()
