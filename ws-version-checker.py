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

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(asctime)s %(thread)d: %(message)s', stream=sys.stdout)
get_ua = None
config = {}
HASH_TYPE = hashlib.algorithms_guaranteed
GITHUB_URL_UA_JAR = 'https://github.com/whitesource/unified-agent-distribution/releases/latest/download/wss-unified-agent.jar'
MAIN_URL_UA_JAR = 'https://unified-agent.s3.amazonaws.com/wss-unified-agent.jar'
CONFIG_FILE = 'params.config'
CONFIG_FILE_HEADER_NAME = 'DEFAULT'
hexdigset_length = 64

# fallback / default values
COMPARED_HASH_METHOD = 'md5'
COMPARE_WITH_WS_GIT = False


################################################################################
def get_config_file(config_file):
    conf_file = ConfigParser()
    conf_file.read(config_file)

    logging.info("Start analyzing config file")
    conf_file_dict = {
        'file_dir': conf_file[CONFIG_FILE_HEADER_NAME].get('fileDir'),
        'file_name': conf_file[CONFIG_FILE_HEADER_NAME].get('fileName'),
        'hash_method': conf_file[CONFIG_FILE_HEADER_NAME].get('comparedHashMethod', fallback=COMPARED_HASH_METHOD),
        'compare_ws_git': conf_file[CONFIG_FILE_HEADER_NAME].getboolean('compareWithWsGit', fallback=COMPARE_WITH_WS_GIT)
    }

    if conf_file_dict['hash_method'] not in HASH_TYPE:
        logging.info(f"The selected hash method <{conf_file_dict['hash_method']}> is invalid")
        sys.exit(1)

    # Checking for missing parameters in the config file
    for param in conf_file_dict:
        if param is None:
            logging.warning("Please conf_file_dict your config parameters")
            sys.exit(1)

    logging.info("Finished analyzing config file")

    return conf_file_dict


def get_args():
    logging.info("Start analyzing arguments")

    parser = argparse.ArgumentParser(description="version-checker parser")
    parser.add_argument('-f', "--fileDir", help="The file directory path", required=True, dest='file_dir')
    parser.add_argument('-n', "--fileName", help="The name of the file to be checked by the tool", dest='file_name')
    parser.add_argument('-m', "--comparedHashMethod", help="One of hashlib.algorithms_guaranteed", dest='hash_method', default=COMPARED_HASH_METHOD, choices=HASH_TYPE)
    parser.add_argument('-g', "--compareWithWsGit", help="True-compared with git version ,false-comparedHashMethod", dest='compare_ws_git', default=COMPARE_WITH_WS_GIT, type=str2bool)

    args = parser.parse_args()
    args_dict = vars(args)  # Convert arg namespace to dictionary

    logging.info(f"Arguments received :{args}")
    logging.info("Finished analyzing arguments")

    return args_dict


################################################################################

def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 'True', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'False', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


#######################################################################################################################
def fetch_local_sem_version():
    # fetch the local file semantic version
    archive = zipfile.ZipFile(config['file_path'], 'r')
    file_prop_path = archive.read('META-INF/maven/org.whitesource/wss-unified-agent-main/pom.properties')
    file_prop_path = str(file_prop_path, 'UTF-8')
    current_ua_user_version = file_prop_path.split('version=')[1].split('groupId')[0].split('\n')[0]
    logging.info(config['file_path'] + " version is : " + current_ua_user_version)

    return current_ua_user_version


def fetch_remote_git_version():
    # fetch the current git version
    ua_response = requests.head(GITHUB_URL_UA_JAR)
    headers = ua_response.headers
    location = headers["location"]
    git_ua_version = re.search('download/v(.*)/wss-unified', location)
    git_ua_version_final = git_ua_version.group(1)

    return git_ua_version_final


def check_version_git_diff():
    current_ua_user_version = fetch_local_sem_version()
    git_ua_version_final = fetch_remote_git_version()

    # compare between user plugin version and current git version and download
    if version.parse(current_ua_user_version) < version.parse(git_ua_version_final):
        download = True
        logging.info(f"A new unified agent version ({git_ua_version_final}) has been found ")
    else:
        download = False
        logging.info(f"You have the latest version ({git_ua_version_final})")

    return download


#######################################################################################################################

def calc_hash_checksum(file_p, link, hash_m):
    global get_ua                                   # set as global to avoid downloading in case hash compare results in a new available version.
    hash_calc = eval('hashlib.' + hash_m + '()')

    if link is None:
        with open(file_p, 'rb') as fh:
            while True:
                data = fh.read(64)
                hash_calc.update(data)
                if not data:
                    break
    else:
        get_ua = requests.get(link, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
        for data in get_ua.iter_content(64):
            hash_calc.update(data)

    if hash_m in ['shake_128', 'shake_256']:
        return hash_calc.hexdigest(hexdigset_length)
    else:
        return hash_calc.hexdigest()


def check_version_hash_diff():
    # fetch the local hash value
    file_hash = calc_hash_checksum(config['file_path'], None, config['hash_method'])
    logging.info(f"{config['hash_method']} checksum-->local : {file_hash}")

    # fetch the remote hash value
    url_hash = calc_hash_checksum(None, MAIN_URL_UA_JAR, config['hash_method'])
    logging.info(f"{config['hash_method']} checksum-->remote :  {url_hash}")

    # compare between local hash version and remote hash version
    if file_hash != url_hash:
        download = True
        logging.info(f"A new unified agent version has been found ")

    else:
        download = False
        logging.info(f"You have the latest version ({file_hash})")

    return download


#######################################################################################################################

def download_new_version(compare_ws_git):
    if compare_ws_git is True:
        logging.info('Start downloading the WhiteSource Unified Agent latest version')
        r = requests.get(GITHUB_URL_UA_JAR, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
        open(config['file_path'], 'wb').write(r.content)
        logging.info('WhiteSource Unified Agent latest version download is completed')
    else:
        open(config['file_path'], 'wb').write(get_ua.content)
        logging.info('WhiteSource Unified Agent latest version was updated')


def compare_versions(compare_ws_git):
    if compare_ws_git:
        is_version_diff = check_version_git_diff()
    else:
        is_version_diff = check_version_hash_diff()

    return is_version_diff


def validate_ua_dir_and_file():
    logging.info("Checking if compared file exists")
    config['file_path'] = os.path.join(config['file_dir'], config['file_name'])
    if os.path.exists(config['file_path']):
        logging.info(f"The compared file : {config['file_path']} exists")
    else:
        logging.warning("The Unified Agent file doesn't exist - please check your fileName and fileDir parameters")
        sys.exit(1)


def read_setup():
    global config

    args = sys.argv[1:]

    if len(args) > 1:
        config = get_args()
    elif len(args) == 1 and os.path.exists(args[0]):    # enables the user to run with any config file naming convention
        config = get_config_file(args[0])
    elif os.path.exists(CONFIG_FILE):                   # used when running the script from the same path of CONFIG_FILE (params.config)
        config = get_config_file(CONFIG_FILE)
    else:
        logging.info("The config file doesn't exist - please check your command")
        sys.exit(1)


def main():
    read_setup()                                        # read configuration from cli / config file
    validate_ua_dir_and_file()                          # validation of the file path

    logging.info("Starting WhiteSource version check")

    if compare_versions(config['compare_ws_git']):      # compare between versions
        download_new_version(config['compare_ws_git'])  # download new version

    logging.info("Completed WhiteSource version check")


if __name__ == '__main__':
    main()
