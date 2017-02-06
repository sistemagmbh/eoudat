# EOUDAT

Eoudat consists in a python package called via command line interface. 
This tool allows to download files from different locations, both from open or protected addresses. It is structured in order to make the download simple and efficent.
The main functionalities are:
- retrieve files from a open http location
- retrieve files from a regular ftp server (through regular authentication)
- retrieve files making use of different secure authentications
- retrieve files from specific platform (i.e. ESA Online Dissemination platform, Copernicus Hub)

The tool can also: mangage to download a list of file, manage multiple download, manage a maximum number of downloads per session and per day, permit to save and store credentials for specific servers.


## REQUIREMENTS:

The tool was tested on Ubuntu 16.04 and Windows 10, but in future it will be available also for other distributions.

The following packages shall be installed in order to run the module:
- Python 2.7 or higher
	- PycURL 
	- Paramiko
	- Cryptography
	 
For Windows users, the *win_install_script/eoudat_pip.bat* script allows installing the needed dependencies; please refer to the installation instructions (EOUDAT_installation_instructions.pdf) for detailed configurations.

## USAGE:

The tool has to be launched from the command line using the following command:

    python <installationPath>/eoudat.py [-h] [-u username] [-p password] [url][-l list_of_URLs] [-s] [-r] [-q daily quota][-c parallel_downloads] [--clean] [-d proxy] [-x 	sci_hub]

### Options and Arguments

| **Option** | **Argument** | **Description** |
| ---------- | ------------ | --------------- |
|  | url | one or more URLs to be downloaded |
| -h | | show this help message and exit |
| -u  | *username* | username for downloading the file(s) (only if needed) |
| -p | *password* | password for the user's account (only if needed) |
|-l | *list_of_URLs* | path to text file which includes a list of files (one URL per line) to be downloaded (the URLs get appended to the URls given in the command line) |
| -s | | the given username and password are written to "~/.eou_cred" (encrypted) |
| -r | | reads the credentials from "~/.eou_cred" (if username and password are provided this option is ignored) |
| -q | *daily_quota* | the maximum number of dowloads performed per day |
| -c | *nr_downloads* | the maximum number of parallel (concurrent) downloads performed at a time |
| -\-clean | | deletes the credential-file if available (if -s is set, the old file gets deleted first and is replaced by a new one) |
| -x | *sci_hub* | downloads the files from a Sci Hub cart file (XML) |
| -d | *proxy* | proxy server, you have to state the proxy and the port, e.g. 127.0.0.1:8080 |


When the tool is launched, it will start with the download of the files, showing a message when the download of a file starts and a message when a file has been downloaded completly.
The files are saved in the directory from which the tool was launched.

### Example

Below is displayed an example of instruction, in order to download a protected file from a ftp address:

    python eoudat.py -u demo -p password ftp://test.rebex.net/pub/example/FtpDownloader.png

## DOCUMENTATION:

The EOUDAT_installation_instructions.pdf provides dependencies and installation instructions for Linux and Windows.

## LICENCE:

MIT License
