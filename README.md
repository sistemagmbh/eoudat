EOUDAT

Eoudat consists in a python package called via command line interface. 
This tool allows to download files from different locations, both from open or protected addresses. It is structured in order to make the download simple and efficent.
The main functionalities are:
- retrieve files from a open http location
- retrieve files from a regular ftp server (through regular authentication)
- retrieve files making use of different secure authentications
- retrieve files from specific platform (i.e. ESA Online Dissemination platform, Copernicus Hub)

The tool can also: mangage to download a list of file, manage multiple download, manage a maximum number of downloads per session and per day, permit to save and store credentials for specific servers.


REQUIREMENTS:

The tool was tested on Ubuntu 16.04 and Windows 10, but in future it will be available also for other distributions.   

The following packages shall be installed in order to run the module:
- Python 2.7 or higher
	- PycURL 
	- Paramiko
	- Cryptography


USAGE:

The following command like shall be provided:
python <installationPath/>eoudat.py [-h] [-u username] [-p password] [url][-l list_of_URLs] [-s] [-r] [-q daily quota][-c parallel_downloads] [--clean] [-d proxy] [-x 	sci_hub] 

Where:
[-h] shows the help message, describing the functionalities of the tool

[-u username] is an optional field, necessary just for files protected by authentication

[-p password] is an optional field, necessary just for files protected by authentication

[url] represent the addresses of the files to download

[-l list_of_URLs] proving a text file (list_of_URLs) which contains a list of URLs, it allows to downloaded all of the file inside the list

[-s] is a command, that allows to save and store authentication credentials

[-r] is a command, that allows to re-use saved credentials

[-q daily quota] allows to set a maximum number of downloaded files per day; if set, this option sets the console on idle after having downloaded the defined daily quota; as soon as the day changes, the tool restarts downloading; this loop ends once all files have been downloaded 

[-c parallel_downloads] allows to configure the number of parallel downloads to be started

[--clean] deletes the file in which the credentials are stored

[-x] allows the user to download files from a Sci Hub cart file

[-d] allows the user to download files behind a proxy, specifying address and port of it


When the tool is launched, it will proceed with the download of the files, showing the status of the downloads. When the “Downloading: 100%” is achieved, a message of complete download will appear. It marks the end of the process.
The files are saved in the directory from which the tool was launched.

Below is displayed an example of instruction, in order to download a protected file from a ftp address:
python <installationPath/>eoudat.py -u username -p password ftp://...../address_of_file_to_download.zip

DOCUMENTATION:

In this repository, a minimum set of supporting documents will be released.


LICENCE:

MIT License
