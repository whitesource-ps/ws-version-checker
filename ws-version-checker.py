import argparse
import hashlib
import logging
import os
import re
import sys
import zipfile
from configparser import ConfigParser

import requests
from packaging import version

# file_handler = logging.FileHandler(filename='version-check.log')
stdout_handler = logging.StreamHandler(sys.stdout)
handlers = [stdout_handler]
logging.basicConfig(level=logging.INFO,
                    format='%(levelname)s %(asctime)s %(thread)d: %(message)s',
                    handlers=handlers
                    )
logger = logging.getLogger()

file_path = ''
config = None
HASH_TYPE = hashlib.algorithms_guaranteed
GITHUB_URL_UA_JAR = 'https://github.com/whitesource/unified-agent-distribution/releases/latest/download/wss-unified-agent.jar'
MAIN_URL_UA_JAR = 'https://unified-agent.s3.amazonaws.com/wss-unified-agent.jar'
CONFIG_FILE = 'params.config'
hexdigset_length = 64


class Configuration:
    def __init__(self):
        global config
        config = ConfigParser()
        config.optionxform = str
        config.read(CONFIG_FILE)

        self.file_dir = config['DEFAULT'].get('fileDir')
        self.file_name = config['DEFAULT'].get('fileName')
        self.hash_method = config['DEFAULT'].get('comparedHashMethod')
        self.compare_ws_git = config['DEFAULT'].getboolean('compareWithWsGit')


class ArgumentsParser:
    def __init__(self):
        """
        :return:
        """
        parser = argparse.ArgumentParser(description="version-checker parser")
        parser.add_argument("-fd", required=False)
        parser.add_argument("-fn", required=False)
        parser.add_argument("-hm", required=False)
        parser.add_argument("-cg", required=False, type=str2bool)

        argument = parser.parse_args()

        if argument.fd:
            self.file_dir = argument.fd
        if argument.fn:
            self.file_name = argument.fn
        if argument.hm:
            self.hash_method = argument.hm
        if argument.cg is not None:
            self.compare_ws_git = argument.cg


def hash_checksum(file_p, link, hash_m):
    hash_mlow = hash_m.lower()
    if hash_mlow in HASH_TYPE:
        hash_calc = eval('hashlib.' + hash_mlow + '()')
    else:
        hash_calc = hashlib.md5()
    if link is None:
        with open(file_p, 'rb') as fh:
            while True:
                data = fh.read(64)
                hash_calc.update(data)
                if not data:
                    break
    else:
        r = requests.get(link, headers={'Cache-Control': 'no-cache'})
        for data in r.iter_content(64):
            hash_calc.update(data)

    if hash_mlow in ['shake_128', 'shake_256']:
        return hash_calc.hexdigest(hexdigset_length)
    else:
        return hash_calc.hexdigest()


def download_new_version_hash_diff():
    file_hash = hash_checksum(file_path, None, config.hash_method)
    logger.info(f"{config.hash_method} checksum_local : {file_hash}")

    url_hash = hash_checksum(None, MAIN_URL_UA_JAR, config.hash_method)
    logger.info(f"{config.hash_method} checksum_remote :  {url_hash}")

    if file_hash != url_hash:
        logging.info('Start downloading the WhiteSource Unified Agent latest version')
        r = requests.get(MAIN_URL_UA_JAR, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
        open(file_path, 'wb').write(r.content)
        logging.info('WhiteSource Unified Agent latest version version download is completed')
    else:
        logger.info(f"You have the latest version ({file_hash})")


def download_new_version_git_diff():
    archive = zipfile.ZipFile(file_path, 'r')
    file_prop_path = archive.read('META-INF/maven/org.whitesource/wss-unified-agent-main/pom.properties')
    file_prop_path = str(file_prop_path, 'UTF-8')
    current_ua_user_version = file_prop_path.split('version=')[1].split('groupId')[0].split('\n')[0]
    logger.info(file_path + " version is : " + current_ua_user_version)

    # fetch the current git version
    ua_response = requests.head(GITHUB_URL_UA_JAR)
    headers = ua_response.headers
    location = headers["location"]
    git_ua_version = re.search('download/v(.*)/wss-unified', location)
    git_ua_version_final = git_ua_version.group(1)

    # compare between user plugin version and current git version and download
    if version.parse(current_ua_user_version) < version.parse(git_ua_version_final):
        logger.info(f"A new unified agent version ({git_ua_version_final}) has been found ")
        logging.info('Start downloading the WhiteSource Unified Agent latest version')
        r = requests.get(GITHUB_URL_UA_JAR, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
        open(file_path, 'wb').write(r.content)
        logging.info('WhiteSource Unified Agent latest version download is completed')
    else:
        logger.info(f"You have the latest version ({git_ua_version_final})")


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 'True', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'False', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def main():
    global config
    global file_path

    args = sys.argv[1:]
    if len(args) >= 8:
        config = ArgumentsParser()
    else:
        config = Configuration()

    file_path = os.path.join(config.file_dir, config.file_name)

    logger.info("Starting version check")
    if config.compare_ws_git:
        download_new_version_git_diff()
    else:
        download_new_version_hash_diff()


if __name__ == '__main__':
    main()
