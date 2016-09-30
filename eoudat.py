#!/usr/bin/env python

import os
import sys
import argparse
import re
import tempfile
import pycurl
import urllib
import paramiko
import time
import base64
import xml.etree.ElementTree as ET
from threading import Thread
from cryptography.fernet import Fernet
from datetime import date

def progress(downloads, threads):
#    finished = [False] * len(downloads)
    shorten = lambda x: x if len(x) < 52 else x[0:28] + '...' + x[-28:]
    if len(downloads) == 1:
        header_message = 'Downloading one file:'
    else:
        header_message = 'Downloading {:d} files:'.format(len(downloads))
    
    def pretty_print(size):
        prefixes = ['', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB']
        for i,v in enumerate(prefixes):
            if size/(1000**(i+1)) == 0:
                return '{:.2f} {:s}'.format(float(size)/(1000**(i)), v)
            #if the end of the list is reached, keep EB as output
            elif v is prefixes[-1]:
                return '{:.2f} {:s}'.format(float(size)/(1000**(i)), v)
    
    #TODO: refactor with list comprehension
    #print downloads
    for f in downloads:
        if not os.path.exists(f[0]):
            while not os.path.exists(f[0]):
                time.sleep(0.05)
    
    #TODO: add pretty print if get_size returns -1
    while not all(t[0].is_alive() == False for t in threads):
        print(header_message)
        for idx,f in enumerate(downloads):
            file_progress = (os.path.getsize(f[0])*100.)/f[1]
            print('{:s} {:5.2f}%'.format(shorten(f[0]), file_progress))
        time.sleep(0.1)
        os.system('cls' if os.name == 'nt' else 'clear')
        
    print(header_message)
    for f in downloads:
        file_progress = (os.path.getsize(f[0])*100.)/f[1]	
        print('{:s}: {:5.2f}%'.format(shorten(f[0]), file_progress))
    Logger().print_log()
    Logger().reset_log()
                

# TODO: check/download ftp with FTP lib(?)
def curl_get_size(url, username=None, password=None):
    c = pycurl.Curl()
    if username != None and password != None:
        c.setopt(pycurl.USERPWD, '%s:%s' % (username, password))
    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.FOLLOWLOCATION, True)
    c.setopt(pycurl.SSL_VERIFYHOST, False)
    c.setopt(pycurl.SSL_VERIFYPEER, False)
    c.setopt(pycurl.NOBODY,True)
    c.perform()
    size = int(c.getinfo(c.CONTENT_LENGTH_DOWNLOAD))
    c.close()
    return size


def ssh_get_size(url, username, password):
    host = url.split('/')[2]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        sftp = ssh.open_sftp()
        size = sftp.stat(url.replace('ssh://', '').replace('sftp://', '').replace(host, '')).st_size
        sftp.close()
        ssh.close()
    except Exception as e:
        raise e
    return size


def get_size(url, username=None, password=None):
    sso = SSO()
    url_type = url.split(':')[0]
    if url_type == 'ssh' or url_type == 'sftp':
        return ssh_get_size(url, username, password)
        
    if sso.is_SSO(url):
        sso.login(url, username, password)
        return sso.get_size(url)
        
    if url_type == 'http' or url_type == 'https':        
        check_http_statuscode(url)
    return curl_get_size(url, username, password)


def get_http_statuscodes(url):
    status_codes = []
    def strip_header(buffer):
        if buffer.startswith('HTTP'):
            buffer = buffer.split(' ')
            code = int(buffer[1])
            message = ' '.join(buffer[2:])
            status_codes.append((code, message))
    
    c = pycurl.Curl()
    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.SSL_VERIFYHOST, False)
    c.setopt(pycurl.SSL_VERIFYPEER, False)
    c.setopt(pycurl.FOLLOWLOCATION, True)
    c.setopt(pycurl.NOBODY, True)
    c.setopt(pycurl.HEADERFUNCTION, strip_header)
    c.perform()
    return status_codes
    
    
def check_http_statuscode(url):
    status_code = get_http_statuscodes(url)[-1]
    if status_code[0] >= 400:
        raise Exception('HTTP Error {:d}: {:s}'.format(status_code[0], status_code[1]))
    
        
def download_curl(url, username, password):
    filename = url.split('/')[-1]
    try:
        with open(filename, 'wb') as f:
            c = pycurl.Curl()
            c.setopt(pycurl.URL, url)
            c.setopt(pycurl.SSL_VERIFYHOST, False)
            c.setopt(pycurl.SSL_VERIFYPEER, False)
            c.setopt(pycurl.FOLLOWLOCATION, True)
            c.setopt(pycurl.WRITEDATA, f)
            if username != None and password != None:
                c.setopt(pycurl.USERPWD, '%s:%s' % (username, password))
            c.perform()
            c.close()
    except Exception as e:
        os.remove(filename)
        raise e
            

def download_http(url, username=None, password=None):
    check_http_statuscode(url)
    sso = SSO()
    if sso.is_SSO(url):
        sso.login(url, username, password)
        sso.download_SSO(url)
    else:
        download_curl(url, username, password)
    
    
def download_ssh(url, username, password):
    filename = url.split('/')[-1]
    host = url.split('/')[2]
    path = url.replace('ssh://', '').replace('sftp://', '').replace(host, '').replace(filename, '')
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        sftp = ssh.open_sftp()
        sftp.get(path + filename, filename)
        sftp.close()
        ssh.close()
    except Exception as e:
        os.remove(filename)
        raise e
    
    
def download_ftp(url, username, password):
    if username == None or password == None:
        username = 'anonymous'
        password = 'anonymous@domain.com'
    download_curl(url, username, password)
    
    
def download(URLs, username, password):
    threads = []
    downloads = []
    logger = Logger()

    if type(URLs) != list:
        URLs = [URLs]
    
    for url in URLs:
        filename = url.split('/')[-1]
        if os.path.exists(filename):
            logger.log('Warning', 'File already exists, skipping: ' + filename)
            continue
            
        url_type = url.split(':')[0]
        try:
            filesize = get_size(url, username, password)
            if filesize < 0:
                logger.log('Warning', 'Could not get filesize for {:s}'.format(url))
            
            if url_type == 'http' or url_type == 'https':
                check_http_statuscode(url)
                threads.append((Thread(target=download_http, args=(url, username, password)), url))
            elif url_type == 'ftp':
                threads.append((Thread(target=download_ftp, args=(url, username, password)), url))
            elif url_type == 'ssh' or url_type == 'sftp':
                threads.append((Thread(target=download_ssh, args=(url, username, password)), url))
            else:
                pass
        except Exception as e:
            logger.log_debug('Error', str(e), url)
            logger.log('Error', str(e), url)
            if os.path.exists(filename):
                os.remove(filename)
            continue
        downloads.append((filename, filesize))

    try:
        for t in threads:
            t[0].start()
    except Exception as e:
        logger.log_debug('Error', str(e), url)
        logger.log('Error', str(e), t[1])
        if os.path.exists(filename):
            os.remove(filename)

    show_progress = Thread(target=progress, args=[downloads, threads])
    show_progress.start()
    for t in threads:
        t[0].join()
    show_progress.join()
    

def load_credentials():
    filename = os.path.expanduser('~') + '/.eou_cred'
    key = 'FRRltba98dCxL9PiYwsvx5nOY6Lwn1GGAwaLUwgloro='
    return key, filename
    
        
def save_credentials(host, username, password):
    key, filename = load_credentials()
    credentials = {}
    if os.path.exists(filename):
        credentials = read_credentials()
    credentials[host] = [username, password]
    
    with open(filename, 'w') as f:
        cypher = Fernet(key)
        for key, value in credentials.iteritems():
            token = cypher.encrypt(key) + '\n' + cypher.encrypt(value[0]) + '\n' + cypher.encrypt(value[1])
            f.write(base64.b64encode(token) + '\n')
    

def read_credentials(requested_host=None):
    key, filename = load_credentials()
    credentials = {}
    try:
        with open(filename, 'r') as f:
            cypher = Fernet(key)
            lines = map(lambda x: x.strip(), f.readlines())
            for line in lines:
                token = base64.b64decode(line).split('\n')
                host = cypher.decrypt(token[0])
                username = cypher.decrypt(token[1])
                password = cypher.decrypt(token[2])
                credentials[host] = [username, password]
    except IOError:
        print('Could not open {:s}.'.format(filename))
        print('Probably the credentials haven\'t been saved with the -s option.')
        exit(0)
    except IndexError:
        print('Could not read {:s}. Delete the file by starting this program with the --clean option.'.format(filename))
        
    if requested_host:
        return credentials[requested_host][0], credentials[requested_host][1]
    else:
        return credentials
        
        
class SSO:
    def __init__(self):
        self.threshold = 1000*1000
        self.cookies = tempfile.mkdtemp() + '/keksi'
        self.logged_in = False
        self.login_failed = False
        self._dummy_filename = 'sso_login.html'
        
        
    def curl(self):
        curl = pycurl.Curl()
        curl.setopt(pycurl.COOKIEFILE, self.cookies)
        curl.setopt(pycurl.COOKIEJAR, self.cookies)
        curl.setopt(pycurl.FOLLOWLOCATION, True)
        curl.setopt(pycurl.SSL_VERIFYHOST, False)
        curl.setopt(pycurl.SSL_VERIFYPEER, False)
        curl.setopt(pycurl.NOBODY, True)
        return curl
        
        
    def is_SSO(self, url):
        if self.logged_in:
            return True
        
        url_type = url.split(':')[0]
        if not (url_type == 'http' or url_type == 'https'):
            return False
        
        # the file is bigger than the threshold, so don't check if it's a SSO
        if curl_get_size(url) > self.threshold:
            return False
        
        filename = url.split('/')[-1]
        download_curl(url, None, None)
        downloaded_file = open(filename, 'r')
        down_file_content = downloaded_file.read()
        downloaded_file.close()
        if re.search('<title>EO SSO</title>', down_file_content):
            return True
        else:
            return False
            
#TODO: try with non-cached (new) product            
#TODO: refactor: remove url
    def check_SSO_login(self, url):
        self.login_failed = True
        if os.path.getsize(self._dummy_filename) < self.threshold:
            with open(self._dummy_filename, 'r') as downloaded_file:
                response = downloaded_file.read()
            os.remove(self._dummy_filename)
            
            sso_regex1 = '<span class="errorMessage" id="loginerror">'
            sso_regex2 = '</span>'
            sso_error = re.search(sso_regex1 + '\n.+\n.+' + sso_regex2, response)
            if sso_error:
                sso_error = sso_error.group(0).replace(sso_regex1, '').replace(sso_regex2, '').strip()
                raise Exception(sso_error)
            
            if re.search('<title>EO SSO</title>', response):
                raise Exception('Could not log into SSO.')
            
            self.logged_in = True
            self.check_OADS(response, url)
                
            """
            oads_response = ET.fromstring(response)
            oads_namespace = re.search('\{.+\}', oads_response.tag).group(0)
            oads_code = oads_response.find(oads_namespace + 'ResponseCode')
            oads_message = oads_response.find(oads_namespace + 'ResponseMessage')
            self.logged_in = True            
            
            if oads_code is not None and oads_code.text != 'ACCEPTED':
                raise Exception('[OADS error] ' + oads_code.text + (': ' + oads_message.text if oads_message is not None else ''))
#TODO: implement polling (?)            
            elif oads_code is not None and oads_code.text == 'ACCEPTED':
                wait = int(oads_response.find(oads_namespace + 'RetryAfter').text)
                print('Authorized for downloading the product, waiting {:d} seconds until it\'s ready'.format(wait))
                time.sleep(wait)
            """
        else:
            os.remove(self._dummy_filename)
            self.logged_in = True
            self.login_failed = False

#TODO: REFACTOR!!!
    def check_OADS(self, response, url):
        oads_response = ET.fromstring(response)
        oads_namespace = re.search('\{.+\}', oads_response.tag).group(0)
        oads_code = oads_response.find(oads_namespace + 'ResponseCode')
        oads_message = oads_response.find(oads_namespace + 'ResponseMessage')
        
        if oads_code is not None and oads_code.text != 'ACCEPTED':
            raise Exception('[OADS error] ' + oads_code.text + (': ' + oads_message.text if oads_message is not None else ''))
#TODO: implement polling (?)            
        elif oads_code is not None and oads_code.text == 'ACCEPTED':
            wait = int(oads_response.find(oads_namespace + 'RetryAfter').text)
            print('Authorized for downloading the product, waiting {:d} seconds until it\'s ready'.format(wait))
            time.sleep(wait)
        
        sucess = False
        
        while not sucess:
            print 'Waiting done, trying again'
            filename = url.split('/')[-1]
            try:            
                c = self.curl()
                c.setopt(pycurl.URL, url)
                c.setopt(pycurl.NOBODY, False)
                c.setopt(pycurl.WRITEFUNCTION, self.download_block)
                c.perform()
            except:
                pass
            
            with open(filename, 'r') as downloaded_file:
                response = downloaded_file.read()
            os.remove(filename)
            
            try:
                oads_response = ET.fromstring(response)
                oads_namespace = re.search('\{.+\}', oads_response.tag).group(0)
                oads_code = oads_response.find(oads_namespace + 'ResponseCode')
                oads_message = oads_response.find(oads_namespace + 'ResponseMessage')
            except:
                sucess = True
                break
            
            if oads_code is not None and oads_code.text != 'ACCEPTED':
                raise Exception('[OADS error] ' + oads_code.text + (': ' + oads_message.text if oads_message is not None else ''))
    #TODO: implement polling (?)            
            elif oads_code is not None and oads_code.text == 'ACCEPTED':
                wait = int(oads_response.find(oads_namespace + 'RetryAfter').text)
                print('Authorized for downloading the product, waiting {:d} seconds until it\'s ready'.format(wait))
                time.sleep(wait)
        
            
            
    def download_SSO(self, url):
        if not self.logged_in:
            return
        
        filename = url.split('/')[-1]
        c = self.curl()
        c.setopt(pycurl.URL, url)
        c.setopt(pycurl.NOBODY, False)
        with open(filename, 'wb') as f:
            c.setopt(pycurl.WRITEFUNCTION, f.write)
            c.perform()
            c.close()

                
#TODO: refactor!
#TODO: back to WRITEFUNCTION = lambda x: 0
#TODO: http://stackoverflow.com/questions/128389/what-are-xml-namespaces-for
#      https://www.google.at/search?client=ubuntu&channel=fs&q=curl+get+only&ie=utf-8&oe=utf-8&gfe_rd=cr&ei=i3vqV6a-Camg8weL7ZOQDA#channel=fs&q=libcurl+get+only
    def get_size(self, url):
        if not self.logged_in:
            return

        size = -1
        c = self.curl()
        c.setopt(pycurl.NOBODY, False)
        c.setopt(pycurl.WRITEFUNCTION, lambda x: 0)
        c.setopt(pycurl.URL, url)
        try:        
            c.perform()
        except pycurl.error:
            size = int(c.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD))
        finally:
            c.close()
        return size
    
    
    def login(self, url, username, password):
        if self.logged_in or self.login_failed:
            return
        
        c = self.curl()        
        c.setopt(pycurl.URL, url)
        c.perform()
        data = urllib.urlencode({'cn':username, 'password':password, 'loginFields':'cn@password', 'loginMethod':'umsso', 'sessionTime':'untilbrowserclose', 'idleTime':'oneday'})
        c.setopt(pycurl.POSTFIELDS, data)
        c.setopt(pycurl.URL, 'https://eo-sso-idp.eo.esa.int:443/idp/umsso20/login?null')
        c.setopt(pycurl.NOBODY, False)
        c.setopt(pycurl.WRITEFUNCTION, self.download_block)
        try:
            c.perform()
        except:
            pass
        finally:
            #TODO: remove check_http_status code (maybe too much requests for the limited quota)
            check_http_statuscode(url)
            self.check_SSO_login(url)
            c.close()
            
        
    def download_block(self, buf):
        with open(self._dummy_filename, 'ab') as f:
            f.write(buf)
        
        if os.path.getsize(self._dummy_filename) > self.threshold:
            return 0


class Logger:
    def __init__(self):
        self.logs = []
        #TODO: remove debugging stuff for release
        self.debug_log = []
                
    def log(self, log_type, message, url=None,):
        if url:
            self.logs.append('[{:s}] {:s} - while downloading {:s}'.format(log_type, message, url))
        else:
            self.logs.append('[{:s}] {:s}'.format(log_type, message))
        
    def print_log(self):
        for log in self.logs:
            print(log)
    #TODO: remove debugging stuff for release
        self.write_debug()
            
    def reset_log(self):
        self.logs = []
        
    #TODO: remove debugging stuff for release
    def log_debug(self, log_type, message, url):
        exc_type, exc_obj, exc_tb = sys.exc_info()
        function_name = exc_tb.tb_frame.f_code.co_name
        line_nr = exc_tb.tb_lineno
        self.debug_log.append('[{:s}] {:s} - while downloading {:s} in {:s}(), line {:d}'.format(log_type, message, url, function_name, line_nr))
    
    def write_debug(self):
        with open(os.path.expanduser('~/eou_debug.log'), 'w') as f:
            for log in self.debug_log:
                f.write(log)

        
SSO = lambda single_SSO = SSO(): single_SSO
Logger = lambda single_logger = Logger(): single_logger
    
if __name__ == '__main__':
    cred_filename = load_credentials()[1]
    parser = argparse.ArgumentParser(prog=sys.argv[0],description='An utility to perform multiple downloads to a sink directory.',epilog='SISTEMA GmbH  <http://www.sistema.at>')
    parser.add_argument('URLs', metavar='url', type=str, nargs='*', help='one or more URLs to be downloaded')
    parser.add_argument('-u', metavar='username', dest='username', help='username for downloading the file(s) (only if needed)')
    parser.add_argument('-p', metavar='password', dest='password', help='password for the user\'s account (only if needed)')
    parser.add_argument('-l', metavar='list_of_URLs', dest='input_list', help='path to text file which includes a list of files (one URL per line) to be downloaded (the URLs get appended to the URls given in the command line)')
    parser.add_argument('-s', action='store_true', dest='store_cred', help='the given username and password are written to the file "{:s}" (encrypted)'.format(cred_filename))
    parser.add_argument('-r', action='store_true', dest='read_cred', help='reads the credentials from "{:s}" (if username and password are provided this option is ignored)'.format(cred_filename))
    parser.add_argument('-q', metavar='daily_quota', dest='daily_quota', help='the maximum number of dowloads performed per day')
    parser.add_argument('--clean', action='store_true', dest='clean_credentials', help='deletes the file "{:s}" if available (if -s is set, the old file gets deleted first and is replaced by a new one)'.format(cred_filename))
    args = parser.parse_args()
    
    if not len(sys.argv) > 1:
        parser.print_help()
        exit(0)
    
    logger = Logger()
    lines = []
    daily_quota = 0
    username = args.username
    password = args.password
    regex = '(http[s]?://.*)|(ftp://.*)|(ssh://.*)|(sftp://.*)'
    URLs = filter(lambda x: re.match(regex, x), args.URLs)
    
    if args.input_list:
        with open(args.input_list, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if re.match(regex, line):
                    URLs.append(line.strip())
                    
    if args.clean_credentials:
        if os.path.exists(cred_filename):
            os.remove(cred_filename)
            logger.log('Info', 'Deleted the credential file {:s}'.format(cred_filename))
            del cred_filename

    if len(URLs) < len(args.URLs) + len(lines):
        logger.log('Warning', 'Not all given links are valid and can be added to the URL list.')
    
    if not URLs:
        print('No valid download links were given, exiting now.')
        logger.print_log()
        exit(0)
        
    if args.daily_quota:
        daily_quota = int(args.daily_quota)
    
    host = URLs[0].split('://')[1].split('/')[0]
    if args.read_cred:
        if username and password:
            logger.log('Warning','Username and password are already provided, option -r is ignored')
        else:
            username, password = read_credentials(host)
        
    if args.store_cred:
        save_credentials(host, username, password)
        
    if username and not password:
        logger.log('Warning', 'Username is given, but no password')
        
    hosts = set()
    map(lambda x: hosts.add(x.split('://')[1].split('/')[0]), URLs)
    if len(hosts) > 1 and username and password:
        logger.log('Warning', 'Credentials are given, but the URLs have different hosts. Because of that it might be possible that not all files are downloaded.')

    if daily_quota:
        while URLs:
            download(URLs[0:daily_quota], username, password)
            del URLs[0:daily_quota]
            
            tomorrow = date.today().replace(day=date.today().day+1)
            till_tomorrow = time.mktime(tomorrow.timetuple()) - time.time()
            
            if URLs:
                print('Download quota for today reached, waiting for {:3.2f} minutes.'.format(till_tomorrow/60))
                time.sleep(till_tomorrow)
    else:
        download(URLs, username, password)
        
    logger.print_log()
    print('Finished all downloads')
