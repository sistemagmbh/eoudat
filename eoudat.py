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
from threading import Thread
from cryptography.fernet import Fernet
from datetime import date

def progress(downloads):
    finished = [False] * len(downloads)
    shorten = lambda x: x if len(x) < 52 else x[0:28] + '...' + x[-28:]
    if len(downloads) == 1:
        header_message = 'Downloading one file:'
    else:
        header_message = 'Downloading {:d} files:'.format(len(downloads))
    
    for f in downloads:
        if not os.path.exists(f[0]):
            while not os.path.exists(f[0]):
                time.sleep(0.01)
    
    while not all(i == True for i in finished):
        print(header_message)
        for idx,f in enumerate(downloads):
            file_progress = (os.path.getsize(f[0])*100.)/f[1]
            print('{:s} {:5.2f}%'.format(shorten(f[0]), file_progress))
            if int(file_progress) >= 100:
                finished[idx] = True
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
    elif sso.is_SSO(url):
        sso.login(url, username, password)
        return sso.get_size(url)
    else:
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
            logger.log('Error', str(e), url)
            os.remove(filename)
            continue
        downloads.append((filename, filesize))

    try:
        for t in threads:
            t[0].start()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger().log('Error', str(e), t[1], fname, exc_tb.tb_linno)

    show_progress = Thread(target=progress, args=[downloads])
    show_progress.start()
    for t in threads:
        t[0].join()
    show_progress.join()
    

#TODO: directory for credentials with hostname
def load_credentials():
    key = 'FRRltba98dCxL9PiYwsvx5nOY6Lwn1GGAwaLUwgloro='
    filename = os.path.expanduser('~') + '/.eou_cred'
    return key, filename
    
        
def save_credentials(username, password):
    key, filename = load_credentials()
    with open(filename, 'w') as f:
        cypher = Fernet(key)
        token = cypher.encrypt(username) + '\n' + cypher.encrypt(password)
        f.write(base64.b64encode(token))
    

def read_credentials():
    key, filename = load_credentials()
    with open(filename, 'r') as f:
        cypher = Fernet(key)
        token = base64.b64decode(f.read()).split('\n')
        username = cypher.decrypt(token[0])
        password = cypher.decrypt(token[1])
        return username, password
        
        
class SSO:
    def __init__(self):
        self.threshold = 1024*1024
        self.cookies = tempfile.mkdtemp() + '/keksi'
        self.logged_in = False
        self.login_failed = False
        
        
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
            
            
    def check_SSO_login(self, filename):
        self.login_failed = True
        if os.path.getsize(filename) < self.threshold:
            with open(filename, 'r') as downloaded_file:
                response = downloaded_file.read()
                if re.search('<span class="errorMessage" id="loginerror">\nInvalid password!\n</span>', response):
                    os.remove(filename)
                    raise Exception('Could not log into SSO: wrong password')
                elif re.search('User\'s entry is not found. Probably you have misspelled the ID or have not registered yet.', response):
                    os.remove(filename)
                    raise Exception ('Could not log into SSO: user does not exist')
                elif re.search('<title>EO SSO</title>', response):
                    os.remove(filename)
                    raise Exception('Could not log into SSO.')
        else:
            self.logged_in = True
            self.login_failed = False
            
            
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

                
    def get_size(self, url):
        if not self.logged_in:
            return
        try:
            c = self.curl()
            c.setopt(pycurl.NOBODY, False)
            c.setopt(pycurl.URL, url)
            c.setopt(pycurl.WRITEFUNCTION, lambda x: 0)
            c.perform()
        except:
            size = int(c.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD))
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
        self._dummy_filename = url.split('/')[-1]
        c.setopt(pycurl.WRITEFUNCTION, self.download_block)
        try:
            c.perform()
        except:
            self.check_SSO_login(self._dummy_filename)
            c.close()
            
        
    def download_block(self, buf):
        with open(self._dummy_filename, 'ab') as f:
            f.write(buf)
        
        if os.path.getsize(self._dummy_filename) > self.threshold:
            return 0


class Logger:
    def __init__(self):
        self.logs = []
                
    def log(self, type, message, url=None, filename=None, line_nr=None):
        if url and filename and line_nr:
            self.logs.append('[{:s}] {:s} while downloading {:s} in {:s}, line {:d}'.format(type, message, url, filename, line_nr))
        elif url:
            self.logs.append('[{:s}] {:s} while downloading {:s}'.format(type, message, url))
        else:
            self.logs.append('[{:s}] {:s}'.format(type, message))
        
    def print_log(self):
        for log in self.logs:
            print(log)
            
    def reset_log(self):
        self.logs = []

        
SSO = lambda single_SSO = SSO(): single_SSO
Logger = lambda single_logger = Logger(): single_logger
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog=sys.argv[0],description='An utility to perform multiple downloads to a sink directory',epilog='SISTEMA GmbH  <http://www.sistema.at>')
    parser.add_argument('URLs', metavar='url', type=str, nargs='*', help='One or more URLs to be downloaded')
    parser.add_argument('-u', metavar='username', dest='username')
    parser.add_argument('-p', metavar='password', dest='password')
    parser.add_argument('-l', metavar='list_of_URLs', dest='input_list')
    parser.add_argument('-s', action='store_true', dest='store_cred')
    parser.add_argument('-r', action='store_true', dest='read_cred')
    parser.add_argument('-q', metavar='daily_quota', dest='daily_quota')
    args = parser.parse_args()
    
    daily_quota = 0
    username = args.username
    password = args.password
    URLs = args.URLs
    
    if args.input_list:
        with open(args.input_list, 'r') as f:
            lines = f.readlines()
            regex = '(http[s]?://.*)|(ftp://.*)|(ssh://.*)|(sftp://.*)'
            for line in lines:
                if re.match(regex, line):
                    URLs.append(line.strip())
    if not URLs:
        parser.print_help()
        exit(0)

    if args.daily_quota:
        daily_quota = int(args.daily_quota)
        
    if args.read_cred:
        if args.username and args.password:
            Logger().log('Warning','Username and password are already provided, option -r is ignored')
        else:
            username, password = read_credentials()
        
    if args.store_cred:
        save_credentials(username, password)

    if daily_quota:
        while URLs:
            download(URLs[0:daily_quota], username, password)
            del URLs[0:daily_quota]
            
            tomorrow = date.today().replace(day=date.today().day+1)
            till_tomorrow = time.mktime(tomorrow.timetuple()) - time.time()
            print('Download quota for today reached, waiting for {:3.2f} minutes.'.format(till_tomorrow/60))
            time.sleep(till_tomorrow)
    else:
        download(URLs, username, password)
        
    print('Finished all downloads')
