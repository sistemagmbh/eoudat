EOUDAT

Eoudat consists in a python package called via command line interface. 
This tool allows to download files from different locations, i.e open http to protected and sso protected addresses. It is structured in order to make the download simple and efficent.
The main functionalities are:
- retrieve files from a open http location
- retrieve files from a regular ftp server (through regular authentication)
- retrieve files by Single Sign On authentication
- retrieve files making use of secure authentication

The tool can also: manage multiple download, manage a maximum number of downloads per day, permit to save and store credentials for specific servers.

REQUIREMENTS:

The tool was tested on Ubuntu 16.04 and Windows 10, but in future it will be available also for other distributions.   

The following packages shall be installed in order to run the module:
- Python 2.7 or higher
	- PycURL 
	- Paramiko

USAGE:

The following command like shall be provided:
python <installationPath/>eoudat.py [-h] [-u username] [-p password] [-l list_of_URLs] [-s] [-r] [-q] [url]
Where:
- [-h] shows an helping message, describing the functionalities of the tool
- [-u Username] is an optional field, necessary just for files protected by authentication
- [-p Password] is an optional field, necessary just for files protected by authentication
- [-s] is a command, that allowed to save and store the credential 
- [-r] is a command, that allowed to re-used some saved credential 
- [-q daily quota] is a command, that manage the maximum download for day 
- [-l list_of_URLs] is a file, which contains a list of URLs to be downloaded
- [url] represent the address of the file to download. 

When the tool is launched, it will proceed with the download of the files, showing the status of the downloads. When the “Downloading: 100%” is achieved, a message of complete download will appear. It marks the end of the process.
The files are saved in the directory from which the tool was launched.

DOCUMENTATION:

In this repository, a minimum set of supporting documents will be released.

LICENCE:

MIT License
