import logging

def giveMeLoggingObject():
	format_str = '%(name)s = %(levelname)s - %(message)s'
	file_name = 'forensics-logging.log'
	logging.basicConfig(format=format_str, filename=file_name, level=logging.INFO)
	loggerObj = logging.getLogger('simple-logger')
	return loggerObj
