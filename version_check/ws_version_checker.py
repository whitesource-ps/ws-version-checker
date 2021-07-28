import argparse
import hashlib
import logging
import os
import pathlib
import re
import subprocess
import sys
import zipfile
from configparser import ConfigParser
from typing import NamedTuple

import requests
from packaging import version

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(asctime)s %(thread)d: %(message)s', stream=sys.stdout)

latest_tool_version = bytes()
config = {}

HASH_TYPE = hashlib.algorithms_guaranteed

DEFAULT_CONFIG_FILE = './version_check/params.config'
CONFIG_FILE_HEADER_NAME = 'DEFAULT'

# fallback / default values
DEFAULT_COMPARED_HASH_METHOD = 'md5'
DEFAULT_COMPARE_WITH_WS_GIT = True

unsigned = "unsigned"
JAR = ".jar"
WSVC_PREFIX = 'WSVC_'
WSVC_ENV_VARS = [WSVC_PREFIX + sub for sub in ('FILE_NAME', 'FILE_DIR', 'COMPARED_HASH_METHOD', 'COMPARE_WITH_WS_GIT')]

ua_properties_file_location = 'META-INF/maven/org.whitesource/wss-unified-agent-main/pom.properties'
ua_git_url = 'https://github.com/whitesource/unified-agent-distribution/releases/latest/download/wss-unified-agent.jar'
ua_main_url = 'https://unified-agent.s3.amazonaws.com/wss-unified-agent.jar'
unified_agent = 'Unified Agent'


# NamedTuple for
class ToolType(NamedTuple):
    git_url: str
    main_url: str
    tool_name: str


TOOLS_TYPES = {ua_properties_file_location: ToolType(git_url=ua_git_url,
                                                     main_url=ua_main_url,
                                                     tool_name=unified_agent)
               }


################################################################################

def get_args(arguments) -> dict:
    """Get configuration arguments"""

    logging.info("Start analyzing arguments.")
    parser = argparse.ArgumentParser(description="version-checker parser")

    parser.add_argument('-c', "--configFile", help="The config file", required=False, dest='conf_f')
    is_config_file = bool(arguments[0] in ['-c', '--configFile'])

    parser.add_argument('-f', "--fileDir", help="The file directory path", required=not is_config_file, dest='file_dir')
    parser.add_argument('-n', "--fileName", help="The name of the file to be checked by the tool", required=not is_config_file, dest='file_name')
    parser.add_argument('-g', "--compareWithWsGit", help="True -compared with git version ,False -comparedHashMethod", dest='compare_with_ws_git', default=DEFAULT_COMPARE_WITH_WS_GIT, type=str2bool)
    parser.add_argument('-m', "--comparedHashMethod", help="One of hashlib.algorithms_guaranteed", dest='compared_hash_method', default=DEFAULT_COMPARED_HASH_METHOD, choices=HASH_TYPE)

    args = parser.parse_args()
    logging.info(f"Arguments received :{args}")

    if args.conf_f is None:
        args_dict = vars(args)
        args_dict.update(get_config_parameters_from_environment_variables())

    elif os.path.exists(args.conf_f):
        logging.info(f"Using {args.conf_f} , additional arguments from the CLI will be ignored")
        args_dict = get_config_file(args.conf_f)
    else:
        logging.error("Config file doesn't exists")
        sys.exit(1)

    logging.info("Finished analyzing arguments.")
    return args_dict


def get_config_file(config_file) -> dict:
    conf_file = ConfigParser()
    conf_file.read(config_file)

    logging.info("Start analyzing config file.")
    conf_file_dict = {
        'file_dir': conf_file[CONFIG_FILE_HEADER_NAME].get('fileDir'),
        'file_name': conf_file[CONFIG_FILE_HEADER_NAME].get('fileName'),
        'compare_with_ws_git': conf_file[CONFIG_FILE_HEADER_NAME].getboolean('compareWithWsGit', fallback=DEFAULT_COMPARE_WITH_WS_GIT),
        'compared_hash_method': conf_file[CONFIG_FILE_HEADER_NAME].get('comparedHashMethod', fallback=DEFAULT_COMPARED_HASH_METHOD)
    }
    if conf_file_dict['compare_with_ws_git'] is False:
        check_if_config_hash_method_is_valid(conf_file_dict['compared_hash_method'])

    conf_file_dict.update(get_config_parameters_from_environment_variables())

    for key, value in conf_file_dict.items():
        if value is None:
            logging.error(f"Please check your {key} parameter-it is missing from the config file")
            sys.exit(1)

    logging.info(f"Config file parameters :{conf_file_dict}")
    logging.info("Finished analyzing the config file.")

    return conf_file_dict


def get_config_parameters_from_environment_variables() -> dict:
    os_env_variables = dict(os.environ)
    wsvc_env_vars_dict = {}
    for variable in WSVC_ENV_VARS:
        if variable in os_env_variables:
            logging.info(f"found {variable} environment variable - will use its value")
            if variable == 'WSVC_COMPARE_WITH_WS_GIT':
                wsvc_env_vars_dict[variable[len(WSVC_PREFIX):].lower()] = str2bool(os_env_variables[variable])  # to assign boolean instead of string
            else:
                wsvc_env_vars_dict[variable[len(WSVC_PREFIX):].lower()] = variable

            if variable == 'WSVC_COMPARED_HASH_METHOD':
                check_if_config_hash_method_is_valid(wsvc_env_vars_dict['compared_hash_method'])

    return wsvc_env_vars_dict


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

def map_the_tool_attributes_to_config():
    """Utilizing the config global dictionary to add variables to be used in the code."""

    file_extension = pathlib.Path(config['file_path']).suffix
    verify_tool_signature_with_whitesource(file_extension)
    prop_file = get_properties_file_location(file_extension)

    tool = TOOLS_TYPES[prop_file]
    config['ws_tool_prop_file'] = prop_file
    config['ws_tool_name'] = tool.tool_name
    config['ws_tool_main_url'] = tool.main_url
    config['ws_tool_git_url'] = tool.git_url


def verify_tool_signature_with_whitesource(file_extension):
    """This method validates that the checked file is a WhiteSource tool. """

    if file_extension == JAR:
        shell_command = subprocess.Popen(f"jarsigner -verify {config['file_path']}", shell=True, stdout=subprocess.PIPE)
        subprocess_return = shell_command.stdout.read()
        if unsigned in str(subprocess_return):
            logging.error("The file to be checked is not a WhiteSource signed tool")
            sys.exit(1)
    else:
        logging.error("The file is not supported by WhiteSource Version-Checker - please check")
        sys.exit(1)


def get_properties_file_location(file_extension):
    """gets properties file full path in the checked tool

    :param file_extension: The tool extension type.
    :type file_extension: str
    :return: The properties file path.
    :rtype: str
    """

    if file_extension == JAR:
        archive = zipfile.ZipFile(config['file_path'], 'r')
        archive_file_list = archive.filelist
        properties_files_types = TOOLS_TYPES.keys()
        properties_file = None

        for element in properties_files_types:
            for item in archive_file_list:
                if element == item.filename:
                    properties_file = element
                    break
        return properties_file
    else:
        logging.error("The file is not supported by WhiteSource Version-Checker - please check")
        sys.exit(1)


#######################################################################################################

def check_versions_git_diff():
    """
    :return: a boolean which indicates whether there is a difference in the git value between local vs remote file.
    :rtype: bool
    """

    current_file_user_version = fetch_local_tool_version()
    git_file_version_final = fetch_remote_git_version()

    if version.parse(current_file_user_version) < version.parse(git_file_version_final):
        to_download = True
        logging.info(f"A new {config['ws_tool_name']} version ({git_file_version_final}) has been found ")
    else:
        to_download = False
        logging.info(f"You have the latest {config['ws_tool_name']} version ({git_file_version_final})")

    return to_download


def fetch_local_tool_version():
    """
    :return:The local tool's version .
    :rtype:str
    """

    archive = zipfile.ZipFile(config['file_path'], 'r')
    file_prop_path = archive.read(config['ws_tool_prop_file'])
    file_prop_path = str(file_prop_path, 'UTF-8')
    current_local_file_version = file_prop_path.split('version=')[1].split('groupId')[0].split('\n')[0]
    logging.info(config['file_path'] + " version is : " + current_local_file_version)

    return current_local_file_version


def fetch_remote_git_version():
    """
    :return: The tool's latest version from the remote repository main branch .
    :rtype:str
    """

    file_response = requests.head(config['ws_tool_git_url'])
    headers = file_response.headers
    location = headers["location"]
    git_version = re.search('download/v(.*)/', location)
    git_version_final = git_version.group(1)

    return git_version_final


#######################################################################################################################

def check_version_hash_diff():
    """
    :return: An indication whether there is a difference in the hash value between local vs remote file
    :rtype: bool
    """

    # fetch the local hash value
    local_file_hash = calc_hash_checksum(config['file_path'], None, config['compared_hash_method'])
    logging.info(f"{config['compared_hash_method']} checksum-->local : {local_file_hash}")

    # fetch the remote hash value
    remote_file_hash = calc_hash_checksum(None, config['ws_tool_main_url'], config['compared_hash_method'])
    logging.info(f"{config['compared_hash_method']} checksum-->remote :  {remote_file_hash}")

    # compare between local hash version and remote hash version
    if local_file_hash == remote_file_hash:
        is_download = False
        logging.info(f"You have the latest {config['ws_tool_name']} version ({local_file_hash})")
    else:
        is_download = True
        logging.info(f"A new {config['ws_tool_name']} version has been found. ")

    return is_download


def calc_hash_checksum(file_p, remote_url, hash_type):
    """Calculating the tool hash value checksum

    :param file_p: The checked file full path ( fileDir+fileName )
    :type file_p: str/None
    :param remote_url: The main url to retrieve the tool file
    :type remote_url: str/None
    :param hash_type: One of the methods from hashlib.algorithms_guaranteed
    :type hash_type: str
    :return: hash value
    :rtype: str
    """

    global latest_tool_version  # set as global to avoid downloading in case hash compare results in a new available version.
    hash_calc = eval('hashlib.' + hash_type + '()')

    if remote_url is None:
        with open(file_p, 'rb') as fh:
            while True:
                data = fh.read()
                hash_calc.update(data)
                if not data:
                    break
    else:
        response = requests.get(remote_url, allow_redirects=True, headers={'Cache-Control': 'no-cache'})
        latest_tool_version = response.content
        hash_calc.update(latest_tool_version)

    if hash_type in ['shake_128', 'shake_256']:
        return hash_calc.hexdigest(64)
    else:
        return hash_calc.hexdigest()


def check_if_config_hash_method_is_valid(hash_method):
    """

    :param hash_method: One of the methods from hashlib.algorithms_guaranteed
    :type hash_method: str
    """

    if hash_method not in HASH_TYPE:
        logging.error(f"The selected hash method <{hash_method}> is not valid")
        sys.exit(1)


#######################################################################################################################

def versions_compared_have_diff(compare_with_ws_git):

    if compare_with_ws_git:
        is_version_diff = check_versions_git_diff()
        return is_version_diff
    else:
        is_version_diff = check_version_hash_diff()
        return is_version_diff


def download_new_version(compare_with_ws_git):
    """Download the new tool version

    :param compare_with_ws_git: if True ,download from git url ,if False download from main url
    :type compare_with_ws_git: bool
    """

    if compare_with_ws_git:
        logging.info(f"Start downloading the WhiteSource {config['ws_tool_name']} latest version.")

        r = requests.get(config['ws_tool_git_url'], allow_redirects=True, headers={'Cache-Control': 'no-cache'})
        open(config['file_path'], 'wb').write(r.content)

        logging.info(f"WhiteSource {config['ws_tool_name']} latest version download is completed.")

    else:
        open(config['file_path'], 'wb').write(latest_tool_version)

        logging.info(f"WhiteSource {config['ws_tool_name']} latest version was updated.")


#######################################################################################################################

def validate_checked_tool_local_file_exist():
    logging.info(f"Checking if the file exists in your environment.")
    config['file_path'] = os.path.join(config['file_dir'], config['file_name'])

    if os.path.exists(config['file_path']):
        logging.info(f"The {config['file_path']} to be checked exists in your environment.")
    else:
        logging.error(f"The file to be checked doesn't exist - please check your fileName and fileDir parameters.")
        sys.exit(1)


#######################################################################################################################

def read_setup():
    """reads the configuration from cli / config file and updates in a global config."""

    global config
    args = sys.argv[1:]
    if len(args) > 0:
        config = get_args(args)
    elif os.path.exists(DEFAULT_CONFIG_FILE):  # used when running the script an IDE same path of CONFIG_FILE (params.config)
        config = get_config_file(DEFAULT_CONFIG_FILE)
    else:
        config = get_config_parameters_from_environment_variables()


#######################################################################################################################

def main():
    read_setup()
    validate_checked_tool_local_file_exist()
    map_the_tool_attributes_to_config()
    logging.info("Starting WhiteSource version check...")

    if versions_compared_have_diff(config['compare_with_ws_git']):
        download_new_version(config['compare_with_ws_git'])

    logging.info(f"WhiteSource {config['ws_tool_name']} version check completed.")


if __name__ == '__main__':
    main()
