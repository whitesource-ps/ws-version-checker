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

# Section for the supported artifacts
# =====================================
properties_file = {'META-INF/maven/org.whitesource/wss-unified-agent-main/pom.properties': 'ws_unified_agent'}
supported_artifacts = {'ws_unified_agent': 'Unified Agent'}
github_url = {'ws_unified_agent': 'https://github.com/whitesource/unified-agent-distribution/releases/latest/download/wss-unified-agent.jar'}
main_url = {'ws_unified_agent': 'https://unified-agent.s3.amazonaws.com/wss-unified-agent.jar'}
# ====================================

get_new_version = None
config = {}

HASH_TYPE = hashlib.algorithms_guaranteed

DEFAULT_CONFIG_FILE = 'params.config'
CONFIG_FILE_HEADER_NAME = 'DEFAULT'
HEXDIGSET_LENGTH = 64

# fallback / default values
DEFAULT_HASH_METHOD = 'md5'
COMPARE_WITH_WS_GIT = True


################################################################################
def get_config_file(config_file):
    conf_file = ConfigParser()
    conf_file.read(config_file)

    logging.info("Start analyzing config file.")
    conf_file_dict = {
        # 'ws_file_type': conf_file[CONFIG_FILE_HEADER_NAME].get('wsFileType'),
        'file_dir': conf_file[CONFIG_FILE_HEADER_NAME].get('fileDir'),
        'file_name': conf_file[CONFIG_FILE_HEADER_NAME].get('fileName'),
        'hash_method': conf_file[CONFIG_FILE_HEADER_NAME].get('comparedHashMethod', fallback=DEFAULT_HASH_METHOD),
        'compare_ws_git': conf_file[CONFIG_FILE_HEADER_NAME].getboolean('compareWithWsGit', fallback=COMPARE_WITH_WS_GIT)
    }

    if conf_file_dict['hash_method'] not in HASH_TYPE:
        logging.error(f"The selected hash method <{conf_file_dict['hash_method']}> is invalid")
        sys.exit(1)

    for key, value in conf_file_dict.items():
        if value is None:
            logging.error(f"Please check your {key} parameter-it is missing from the config file")
            sys.exit(1)

    logging.info(f"Config file parameters :{conf_file_dict}")
    logging.info("Finished analyzing the config file.")

    return conf_file_dict


def get_args(arguments):
    logging.info("Start analyzing arguments.")
    parser = argparse.ArgumentParser(description="version-checker parser")

    parser.add_argument('-c', "--configFile", help="The config file", required=False, dest='conf_f')
    is_config_file = bool(arguments[0] in ['-c', '--configFile'])

    parser.add_argument('-f', "--fileDir", help="The file directory path", required=not is_config_file, dest='file_dir')
    parser.add_argument('-n', "--fileName", help="The name of the file to be checked by the tool", required=not is_config_file, dest='file_name')
    parser.add_argument('-m', "--comparedHashMethod", help="One of hashlib.algorithms_guaranteed", dest='hash_method', default=DEFAULT_HASH_METHOD, choices=HASH_TYPE)
    parser.add_argument('-g', "--compareWithWsGit", help="True-compared with git version ,false-comparedHashMethod", dest='compare_ws_git', default=COMPARE_WITH_WS_GIT, type=str2bool)

    args = parser.parse_args()
    logging.info(f"Arguments received :{args}")

    if args.conf_f is None:
        args_dict = vars(args)

    elif os.path.exists(args.conf_f):
        args_dict = get_config_file(args.conf_f)
    else:
        logging.error("Config file doesn't exists")
        sys.exit(1)

    logging.info("Finished analyzing arguments.")
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


################################################################################
def fetch_prop_file():
    archive = zipfile.ZipFile(config['file_path'], 'r')
    archive_file_list = archive.filelist
    properties_file_keys = properties_file.keys()
    ws_file_type = None

    for key in properties_file_keys:
        for item in archive_file_list:
            if key == item.filename:
                ws_file_type = key

    if ws_file_type is None:
        logging.error("The file is not supported by WhiteSource Version-Checker - please check")
        sys.exit(1)
    else:
        return ws_file_type


def fetch_local_sem_version(file_prop):
    # fetch the local file semantic version
    archive = zipfile.ZipFile(config['file_path'], 'r')
    file_prop_path = archive.read(file_prop)
    file_prop_path = str(file_prop_path, 'UTF-8')
    current_file_user_version = file_prop_path.split('version=')[1].split('groupId')[0].split('\n')[0]
    logging.info(config['file_path'] + " version is : " + current_file_user_version)

    return current_file_user_version


def fetch_remote_git_version(git_url):
    # fetch the current git version
    file_response = requests.head(git_url)
    headers = file_response.headers
    location = headers["location"]
    git_version = re.search('download/v(.*)/', location)
    git_version_final = git_version.group(1)

    return git_version_final


def check_version_git_diff(prop_file, git_url_address):
    current_file_user_version = fetch_local_sem_version(prop_file)
    git_file_version_final = fetch_remote_git_version(git_url_address)

    # compare between user plugin version and current git version and download
    if version.parse(current_file_user_version) < version.parse(git_file_version_final):
        is_download = True
        logging.info(f"A new {supported_artifacts[config['ws_file_type']]} version ({git_file_version_final}) has been found ")
    else:
        is_download = False
        logging.info(f"You have the latest {supported_artifacts[config['ws_file_type']]} version ({git_file_version_final})")

    return is_download


#######################################################################################################################

def calc_hash_checksum(file_p, remote_url, hash_type):
    global get_new_version  # set as global to avoid downloading in case hash compare results in a new available version.
    hash_calc = eval('hashlib.' + hash_type + '()')

    if remote_url is None:
        with open(file_p, 'rb') as fh:
            while True:
                data = fh.read(64)
                hash_calc.update(data)
                if not data:
                    break
    else:
        get_new_version = requests.get(remote_url, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
        for data in get_new_version.iter_content(64):
            hash_calc.update(data)

    if hash_type in ['shake_128', 'shake_256']:
        return hash_calc.hexdigest(HEXDIGSET_LENGTH)
    else:
        return hash_calc.hexdigest()


def check_version_hash_diff(remote_file):
    # fetch the local hash value
    local_file_hash = calc_hash_checksum(config['file_path'], None, config['hash_method'])
    logging.info(f"{config['hash_method']} checksum-->local : {local_file_hash}")

    # fetch the remote hash value
    remote_file_hash = calc_hash_checksum(None, remote_file, config['hash_method'])
    logging.info(f"{config['hash_method']} checksum-->remote :  {remote_file_hash}")

    # compare between local hash version and remote hash version
    if local_file_hash == remote_file_hash:
        is_download = False
        logging.info(f"You have the latest {supported_artifacts[config['ws_file_type']]} version ({local_file_hash})")
    else:
        is_download = True
        logging.info(f"A new {supported_artifacts[config['ws_file_type']]} version has been found. ")

    return is_download


#######################################################################################################################

def download_new_version(compare_with_ws_git):
    if compare_with_ws_git:
        logging.info(f"Start downloading the WhiteSource {supported_artifacts[config['ws_file_type']]} latest version.")
        r = requests.get(github_url[config['ws_file_type']], allow_redirects=True, headers={'Cache-Control': 'no-cache'})
        open(config['file_path'], 'wb').write(r.content)
        logging.info(f"WhiteSource {supported_artifacts[config['ws_file_type']]} latest version download is completed.")
    else:
        open(config['file_path'], 'wb').write(get_new_version.content)
        logging.info(f"WhiteSource {supported_artifacts[config['ws_file_type']]} latest version was updated.")


def versions_compared_have_diff(compare_with_ws_git):
    if compare_with_ws_git:
        for key, value in properties_file.items():
            if value == config['ws_file_type']:
                prop_fil = key
                is_version_diff = check_version_git_diff(prop_fil, github_url[config['ws_file_type']])
                return is_version_diff
    else:
        is_version_diff = check_version_hash_diff(main_url[config['ws_file_type']])
        return is_version_diff


def validate_local_file_exist():
    logging.info(f"Checking if the file exists in your environment.")
    config['file_path'] = os.path.join(config['file_dir'], config['file_name'])
    if os.path.exists(config['file_path']):
        config['ws_file_type'] = properties_file[fetch_prop_file()]
        logging.info(f"The {supported_artifacts[config['ws_file_type']]} exists at: {config['file_path']} .")
    else:
        logging.error(f"The file to be checked doesn't exist - please check your fileName and fileDir parameters.")
        sys.exit(1)


def read_setup():
    global config
    args = sys.argv[1:]
    if len(args) > 0:
        config = get_args(args)
    elif os.path.exists(DEFAULT_CONFIG_FILE):  # used when running the script from the same path of CONFIG_FILE (params.config)
        config = get_config_file(DEFAULT_CONFIG_FILE)


def main():
    read_setup()  # read the configuration from cli / config file
    validate_local_file_exist()  # validation of the file path

    logging.info("Starting WhiteSource version check.")

    if versions_compared_have_diff(config['compare_ws_git']):  # compare between versions
        download_new_version(config['compare_ws_git'])  # download new version

    logging.info(f"WhiteSource {supported_artifacts[config['ws_file_type']]} version check completed.")


if __name__ == '__main__':
    main()
