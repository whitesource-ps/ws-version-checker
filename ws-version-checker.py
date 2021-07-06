import argparse
import hashlib
import logging
import os
import re
import sys
import zipfile
from configparser import ConfigParser, MissingSectionHeaderError

import requests
from packaging import version

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(asctime)s %(thread)d: %(message)s', stream=sys.stdout)

config = None
HASH_TYPE = hashlib.algorithms_guaranteed
GITHUB_URL_UA_JAR = 'https://github.com/whitesource/unified-agent-distribution/releases/latest/download/wss-unified-agent.jar'
MAIN_URL_UA_JAR = 'https://unified-agent.s3.amazonaws.com/wss-unified-agent.jar'
CONFIG_FILE = 'params.config'
hexdigset_length = 64


################################################################################
def get_config_file():
    conf_file = ConfigParser()
    conf_file.optionxform = str
    conf_file.read(CONFIG_FILE)

    try:
        logging.info("Start analyzing config file")
        conf_file.file_dir = conf_file['DEFAULT'].get('fileDir')
        conf_file.file_name = conf_file['DEFAULT'].get('fileName')
        conf_file.hash_method = conf_file['DEFAULT'].get('comparedHashMethod')
        conf_file.compare_ws_git = conf_file['DEFAULT'].getboolean('compareWithWsGit')

        check = [conf_file.file_name, conf_file.file_dir, conf_file.compare_ws_git, conf_file.hash_method]
        for param in check:
            if param is None:
                raise TypeError

    except TypeError:
        logging.warning("The Version-Checker didn't run - Please check you are not missing the expected variables.")  # handle missing / commented variables
        exit(-1)
    except ValueError:
        logging.warning("compareWithWsGit value is not boolean.")
        exit(-1)
    logging.info(conf_file.defaults())
    logging.info("finished analyzing config file")

    return conf_file


def get_args():
    logging.info("Start analyzing arguments")

    parser = argparse.ArgumentParser(description="version-checker parser")
    parser.add_argument('-f', "--fileDir", help="The file directory path", required=True, dest='file_dir')
    parser.add_argument('-n', "--fileName", help="The name of the file to be checked by the tool", required=True, dest='file_name', default="wss-unified-agent.jar")
    parser.add_argument('-m', "--comparedHashMethod", help="One of hashlib.algorithms_guaranteed", required=True, dest='hash_method', default='md5')
    parser.add_argument('-g', "--compareWithWsGit", help="True-compared with git version ,false-comparedHashMethod", required=True, dest='compare_ws_git', default=False, type=str2bool)

    args = parser.parse_args()

    logging.info(f"Arguments received :{args}")
    logging.info("finished analyzing arguments")

    return args


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
def local_git_version():
    # fetch the local git version
    archive = zipfile.ZipFile(config.file_path, 'r')
    file_prop_path = archive.read('META-INF/maven/org.whitesource/wss-unified-agent-main/pom.properties')
    file_prop_path = str(file_prop_path, 'UTF-8')
    current_ua_user_version = file_prop_path.split('version=')[1].split('groupId')[0].split('\n')[0]
    logging.info(config.file_path + " version is : " + current_ua_user_version)

    return current_ua_user_version


def remote_git_version():
    # fetch the current git version
    ua_response = requests.head(GITHUB_URL_UA_JAR)
    headers = ua_response.headers
    location = headers["location"]
    git_ua_version = re.search('download/v(.*)/wss-unified', location)
    git_ua_version_final = git_ua_version.group(1)

    return git_ua_version_final


def version_git_diff():
    current_ua_user_version = local_git_version()
    git_ua_version_final = remote_git_version()

    # compare between user plugin version and current git version and download
    if version.parse(current_ua_user_version) < version.parse(git_ua_version_final):
        download = True
        logging.info(f"A new unified agent version ({git_ua_version_final}) has been found ")
    else:
        download = False
        logging.info(f"You have the latest version ({git_ua_version_final})")

    return download


#######################################################################################################################

def hash_checksum(file_p, link, hash_m):
    global config
    hash_mlow = hash_m.lower()
    if hash_mlow in HASH_TYPE:
        hash_calc = eval('hashlib.' + hash_mlow + '()')
    else:
        hash_calc = hashlib.md5()
        config.hash_method = hash_calc.name
        logging.info(f"The selected has method <{hash_m}> is not valid , using the default {config.hash_method}")
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


def version_hash_diff():
    # fetch the local hash value
    file_hash = hash_checksum(config.file_path, None, config.hash_method)
    logging.info(f"{config.hash_method} checksum_local : {file_hash}")

    # fetch the remote hash value
    url_hash = hash_checksum(None, MAIN_URL_UA_JAR, config.hash_method)
    logging.info(f"{config.hash_method} checksum_remote :  {url_hash}")

    # compare between local hash version and remote hash version
    if file_hash != url_hash:
        download = True
        logging.info(f"A new unified agent version has been found ")

    else:
        download = False
        logging.info(f"You have the latest version ({file_hash})")

    return download


#######################################################################################################################

def compare_versions(compare_ws_git):
    if compare_ws_git:
        result = version_git_diff()
    else:
        result = version_hash_diff()

    return result


def validate_dir_and_file():
    try:
        config.file_path = os.path.join(config.file_dir, config.file_name)
        if not os.path.exists(config.file_path):
            raise FileNotFoundError
    except FileNotFoundError:
        logging.warning("The Unified Agent file doesn't exist - please check your fileName and fileDir parameters")
        exit(-1)

    return config.file_path


def download_new_version(compare, compare_ws_git):
    if compare is True:
        if compare_ws_git is True:
            logging.info('Start downloading the WhiteSource Unified Agent latest version')
            r = requests.get(GITHUB_URL_UA_JAR, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
            open(config.file_path, 'wb').write(r.content)
            logging.info('WhiteSource Unified Agent latest version download is completed')
        else:
            logging.info('Start downloading the WhiteSource Unified Agent latest version')
            r = requests.get(MAIN_URL_UA_JAR, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
            open(config.file_path, 'wb').write(r.content)
            logging.info('WhiteSource Unified Agent latest version version download is completed')


def main():
    global config
    global CONFIG_FILE

    try:
        args = sys.argv[1:]
        if len(args) == 1:  # enables the user to run with any config file naming convention
            try:
                CONFIG_FILE = args[0]
                if not os.path.exists(CONFIG_FILE):
                    raise FileNotFoundError
            except FileNotFoundError:
                logging.info("The config file doesn't exist locally- please check your command")
                exit(-1)

        if len(args) > 1:
            config = get_args()
        else:
            config = get_config_file()

        validate_dir_and_file()

        logging.info("Starting WhiteSource version check")

        compare = compare_versions(config.compare_ws_git)

        download_new_version(compare, config.compare_ws_git)

        logging.info("Completed WhiteSource version check")
        exit(0)

    except MissingSectionHeaderError:
        logging.warning("The Version-Checker didn't run -The config file header is missing.")
        exit(-1)
    except Exception:
        logging.warning("The Version-Checker didn't run - Please check your setup or address WhiteSource Support team ")
        exit(-1)


if __name__ == '__main__':
    main()
