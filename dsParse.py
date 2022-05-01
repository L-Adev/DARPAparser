#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import pandas as pd
from pandas.io.json import json_normalize
import gzip
import time
import glob
from colorama import Fore, Back, init
from io import BytesIO
import uuid
import py7zr
import pyodbc
import warnings

json_buffer = BytesIO()
init(autoreset=True)
__author__ = "Luke Fairhead"
__copyright__ = "Built by DevSpace.net.au to use as permitted by Jessemyn Modini"
__credits__ = "Luke Fairhead"
__license__ = "N/A"
__version__ = "1.1.2 - April 2022"
__maintainer__ = "N/A"
__email__ = f"Luke@DevSpace.net.au"
__status__ = "Production"

warnings.simplefilter(action='ignore', category=FutureWarning)

with open("EventLib\EventLog.json", 'r') as eventLogJson:
	eventLog = json.loads(eventLogJson.read())


# The timestamps as provided by the previous scripts.
traceTimestamps = {
	3.2: [(4, 9, 46), (4, 9, 48), (4, 10, 22), (4, 10, 26), (4, 10, 30), (4, 10, 31), (4, 10, 40), (4, 10, 49), (4, 10, 51), (4, 10, 53), (4, 11, 9)],
	4.5: [(4, 12, 28), (4, 12, 30)],
	3.12: [(6, 13, 36)],
	3.15: [(7, 12, 43), (7, 12, 46), (7, 12, 47), (7, 12, 48), (7, 12, 51), (7, 12, 53), (7, 18, 10)],
	4.9: [(7, 13, 50), (7, 14, 2), (7, 14, 10), (7, 14, 15), (7, 14, 20), (7, 14, 22), (7, 14, 25), (7, 14, 28)]
}
theiaTimestamps = {
	4.6: [(4, 12, 28), (4, 13, 42)],
	3.3: [(4, 14, 55), (4, 14, 51), (4, 9, 58), (4, 14, 31), (4, 14, 35), (4, 13, 41)],
	3.11: [(6, 12, 26), (6, 12, 44), (6, 12, 50), (6, 12, 51), (6, 12, 53), (6, 13, 3), (6, 13, 9), (6, 13, 17), (6, 13, 26), (6, 12, 57)],
	4.8: [(7, 13, 50), (7, 14, 4)]
}
fivedTimestamps = {
	4.4: [(3, 13, 19), (3, 13, 38), (3, 13, 49), (3, 14, 49), (3, 15, 7)],
	3.4: [(5, 10, 0), (5, 10, 1), (5, 10, 3), (5, 10, 7), (5, 10, 9), (5, 10, 15), (5, 10, 39), (5, 10, 40)],
	3.10: [(6, 11, 13), (6, 11, 14)]
}

# To setup timestamp libraries for each script, this also includes the relevant PDF Section within the output now to help link things through.
def setupTimestamps(timestamp):
	malicious_timestamp_list = []
	for sc in timestamp:
		for stamp in timestamp[sc]:
			currenttime = int(str((1522987200 + (stamp[0] * 24 + stamp[1]) * 60 * 60) + (stamp[2] * 60)) + '000000000')
			starttime = currenttime - 120000000000
			endtime = currenttime + 120000000000
			pdfSection = sc
			malicious_timestamp_list.append((pdfSection, starttime, endtime))  # , msglist))
		malicious_timestamp_list = sorted(malicious_timestamp_list)
	return malicious_timestamp_list

# This module takes your processed .json chunks and appends them to a .json.gz file (for compression)
def writeGz(textToWrite, fileName):
	with gzip.open(f'{fileName.replace(".json", "")}.json.gz', 'a+') as fout:
		fout.write(json.dumps(textToWrite).encode('utf-8'))
	fout.close()


def parseFiles(startFolder, blocksize, timestampList):
	display = pd.options.display                # Pandas dataframe settings, assisted with data validation - can be removed.
	display.max_columns = 1000                  # Pandas dataframe settings, assisted with data validation - can be removed.
	display.max_rows = 1000                     # Pandas dataframe settings, assisted with data validation - can be removed.
	display.max_colwidth = 1000                 # Pandas dataframe settings, assisted with data validation - can be removed.
	display.width = 5000                        # Pandas dataframe settings, assisted with data validation - can be removed.
	start_time = time.time()                    # Start time parameter (for metrics)
	prevTime = time.time()                      # Start time parameter (for metrics)
	uiUpdate = 1                                # Frequency (in seconds) that you would like the processed qty + duration to refresh in the CLI
	chunk = 1                                   # Start chunk variable declaration.
	init(autoreset=True)                        # Colorama settings, not really required but makes it look cool :)
	processed = 0                               # Processed count variable declaration
	allFiles = [g for g in glob.glob(startFolder + "/*.json")]  # As we aren't reading from the .7z, this loops through all .JSON in the specified folder.
	for currentFile in allFiles:
		chunk = 1
		rawFileName = currentFile.replace(startFolder, '')
		print(f'{Fore.LIGHTWHITE_EX}{"***" * 25}\n{Fore.LIGHTMAGENTA_EX}Processing: {Fore.LIGHTWHITE_EX}{rawFileName}.\n{Fore.LIGHTWHITE_EX}{"***" * 25}')
		jsonFile = pd.read_json(currentFile, lines=True, chunksize=blocksize, convert_dates=False)
		for thisChunk in jsonFile:
			main = pd.DataFrame(thisChunk)                                          # Set up DataFrame for this chunk of lines
			json_struct = json.loads(main.to_json(orient="records"))                # Tidy things up a lil
			df_flat = pd.io.json.json_normalize(json_struct)                        # Flatten out the JSON so that all fields are exposed
			df_flat.fillna('')                                                      # Tidy things up a lil
			df_flat['recordUid'] = main.apply(lambda _: uuid.uuid4(), axis=1)       # Add a new GUID for each record (PrimaryKey for databasing purposes)
			df_flat['Source'] = currentFile                                         # Add source file field to easily refer back (for validation purposes)
			# timestampList = [(3.3, 1522900800001712194, 1522900800001712194)]     # Declare custom PDF Sections and timestamps here for testing of logic. -- Should be turned off.




			for pdfSection, start, end in timestampList:                            # Check each timestamp list, if there is a value within this chunk that matches:
				df_flat.loc[(df_flat['timestamp'] >= start) & (df_flat['timestamp'] <= end), 'label'] = 'Within Attack Range'   # Change label to "Within Attack Range""
				df_flat.loc[(df_flat['timestamp'] >= start) & (df_flat['timestamp'] <= end), 'pdfSection'] = pdfSection         # Change pdfSection to the matching pdfSection in timestamps/
				matches = df_flat.loc[df_flat['label'].isin(['Within Attack Range'])].shape                                     # get a count of Attack Range matches
				matches = matches[0]                                                                                            # As above


				if matches > 0:                                                                          # If there are timestamp matches...
					print(f"{pdfSection} Has timezone matches!")                                         # Alert user
					pdfSection = str(pdfSection)
					eventItems = [item for item in eventLog[pdfSection]]                                 # Get all IOC for this pdfSection from your EventLog.json
					for k in eventItems:                                                                 # If the IOC matches, and the timestamp matches, set flag to ATTACK.
						try:
							df_flat.loc[(df_flat['label'] == 'Within Attack Range') & (df_flat[list(k)] == pd.Series(k)).all(axis=1), 'label'] = 'Attack'
							attackCount = df_flat.loc[df_flat['label'].isin(['Attack'])].shape
							attackCount = attackCount[0]
							if attackCount:
								print('Attack found!')
						except KeyError:
							pass
			processed += blocksize                                                                        # Increase processed count by the blocksize.
			if round((time.time() - prevTime), 2) >= uiUpdate:                                            # update CLI
				prevTime = time.time()
				print(
					f"\r{Fore.LIGHTMAGENTA_EX}Processed: {Fore.LIGHTWHITE_EX}{processed} ... {Fore.LIGHTMAGENTA_EX}Runtime: {Fore.LIGHTWHITE_EX}{round((time.time() - start_time), 2)} seconds... ({Fore.LIGHTGREEN_EX}{round(processed / round((time.time() - start_time), 2), 2)} p/s{Fore.LIGHTWHITE_EX})",
					end="")
			dfJson = df_flat.to_json(default_handler=str, orient='records', lines=True).replace('}', '},')[:-2]                     # The below reformates and cleans up the .json file for output.
			if chunk == 1:
				dfJson = '{"data":' + dfJson
			else:
				dfJson = ',' + df_flat.to_json(default_handler=str, orient='records', lines=True).replace('}', '},')[:-2]
			writeGz(textToWrite=dfJson, fileName=f'{startFolder}/Processed/{rawFileName}')
			chunk += 1                                                                                                              # Process the next chunk
		writeGz(textToWrite="}", fileName=f'{startFolder}/Processed/{rawFileName}')                                                 # Process the next .JSON file

# This just prints the menu / title information etc..
def printSplash():
	print(f"""{Fore.LIGHTWHITE_EX}                                                      
██████{Fore.LIGHTMAGENTA_EX}╗ {Fore.LIGHTWHITE_EX}███████{Fore.LIGHTMAGENTA_EX}╗        {Fore.LIGHTWHITE_EX}██████{Fore.LIGHTMAGENTA_EX}╗  {Fore.LIGHTWHITE_EX}█████{Fore.LIGHTMAGENTA_EX}╗ {Fore.LIGHTWHITE_EX}██████{Fore.LIGHTMAGENTA_EX}╗ {Fore.LIGHTWHITE_EX}███████{Fore.LIGHTMAGENTA_EX}╗{Fore.LIGHTWHITE_EX}███████{Fore.LIGHTMAGENTA_EX}╗
{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔══{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╗{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔════╝        {Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔══{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╗{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔══{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╗{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔══{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╗{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔════╝{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔════╝
{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║  {Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║{Fore.LIGHTWHITE_EX}███████{Fore.LIGHTMAGENTA_EX}╗  {Fore.LIGHTWHITE_EX}███{Fore.LIGHTMAGENTA_EX}╗  {Fore.LIGHTWHITE_EX}██████{Fore.LIGHTMAGENTA_EX}╔╝{Fore.LIGHTWHITE_EX}███████{Fore.LIGHTMAGENTA_EX}║{Fore.LIGHTWHITE_EX}██████{Fore.LIGHTMAGENTA_EX}╔╝{Fore.LIGHTWHITE_EX}███████{Fore.LIGHTMAGENTA_EX}╗{Fore.LIGHTWHITE_EX}█████{Fore.LIGHTMAGENTA_EX}╗  
{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║  {Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║╚════{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║  ╚══╝  {Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔═══╝ {Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔══{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔══{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╗╚════{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}╔══╝  
{Fore.LIGHTWHITE_EX}██████{Fore.LIGHTMAGENTA_EX}╔╝{Fore.LIGHTWHITE_EX}███████{Fore.LIGHTMAGENTA_EX}║        {Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║     {Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║  {Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║{Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║  {Fore.LIGHTWHITE_EX}██{Fore.LIGHTMAGENTA_EX}║{Fore.LIGHTWHITE_EX}███████{Fore.LIGHTMAGENTA_EX}║{Fore.LIGHTWHITE_EX}███████{Fore.LIGHTMAGENTA_EX}╗
{Fore.LIGHTMAGENTA_EX}╚═════╝ ╚══════╝        ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝""")
	print(f"{Fore.LIGHTWHITE_EX}***" * 25)
	scriptInfo = [f"{Fore.LIGHTWHITE_EX}Author    : {Fore.LIGHTMAGENTA_EX}{__author__}",
	              f"{Fore.LIGHTWHITE_EX}Copyright : {Fore.LIGHTMAGENTA_EX}{__copyright__}",
	              f"{Fore.LIGHTWHITE_EX}License   : {Fore.LIGHTMAGENTA_EX}{__license__}",
	              f"{Fore.LIGHTWHITE_EX}Version   : {Fore.LIGHTMAGENTA_EX}{__version__}",
	              f"{Fore.LIGHTWHITE_EX}Contact   : {Fore.LIGHTMAGENTA_EX}{__email__} 🚀",
	              f"{Fore.LIGHTWHITE_EX}Status    : {Fore.LIGHTMAGENTA_EX}{__status__}"]
	for info in scriptInfo:
		print(info)
	print(f"{Fore.LIGHTWHITE_EX}***" * 25)

# To enable reading from .7z rather than individual .JSON files, turned off for more control. Can be re-enabled easy enough.
# def zipReader(loc):
# 	with py7zr.SevenZipFile('sample.7z', mode='r') as z:
# 		z.extractall()

if __name__ == '__main__':
	printSplash()
	print(Fore.LIGHTYELLOW_EX + 'Initializing...  ', end="\b")
	for i in range(59):
		time.sleep(0.01)                                            # Not gonna lie, this part does nothing - but it looks really cool tho
		print(Fore.LIGHTGREEN_EX + '█ ', end='\b')
	time.sleep(0.025)
	print('')
	timestamps = setupTimestamps(traceTimestamps)
	jsonLib = input("Please input the location of your JSON files: ")
	parseFiles(jsonLib, 10000, timestamps)  # The 10000 here indicates the chunk size for the program to read. Lower it if your computer cannot handle 10,000 (or raise it)
