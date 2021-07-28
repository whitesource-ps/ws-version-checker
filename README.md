![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/release/whitesource-ps/ws-version-checker)](https://github.com/whitesource-ps/ws-version-checker/releases/latest)   
[![Build and Publish](https://github.com/whitesource-ps/ws-version-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-version-checker/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)

# WhiteSource Version Checker
The script enables checking the WhiteSource tools , validate whether there is a new version and update it accordingly.
### Supported tools 
- [WhiteSource Unified Agent](https://whitesource.atlassian.net/wiki/spaces/WD/pages/804814917/Unified+Agent+Overview).

### How to use the script
- Run on your local machine where the tool is stored.
- Run as part of your CI process , prior of using one of the supported tools.

### What does the script do?
The script checks the tool version by one of the following :
1. Compare of the local version file hash value (based on [hashlib.algorithms_guaranteed](https://github.com/python/cpython/blob/main/Lib/hashlib.py)) with the latest version from WhiteSource.
2. Compare of the local version file semantic versioning with the WhiteSource tool GitHub repo latest release link - [for example - Unified Agent](https://github.com/whitesource/unified-agent-distribution/releases) .

### Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

### Prerequisites
- Python 3.6 or above.
- Java JDK 8 ,Java JDK 11 ( in favor of jarsigner ).  

### Installation
1. Download and unzip **ws-version-checker.zip**.
2. From the command line, navigate to the ws-version-checker directory and install the package:  
   `pip install -r requirements.txt`. 
3. Edit the `/version_check/params.config` file and update the relevant parameters (see the configuration parameters below) or
   use a cmd line for running the `/version_check/ws_version_checker.py` script.
    
### Configuration Parameters
```
=====================================================================================================================================================================================================
| config file         | cli                        | Environment Variables     | Default  | Optional values                   | Description                                                          |
=====================================================================================================================================================================================================
| fileDir             | -f,  --fileDir             | WSVC_FILE_DIR             |          |                                   | The file directory path.                                             |
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| fileName            | -n,  --fileName            | WSVC_FILE_NAME            |          |                                   | The name of the file to be checked by the tool.                      |
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| compareWithWsGit    | -g,  --compareWithWsGit    | WSVC_COMPARE_WITH_WS_GIT  | True     | True / False                      | If True -compared with git version ,if false use comparedHashMethod. |
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| comparedHashMethod  | -m,  --comparedHashMethod  | WSVC_COMPARED_HASH_METHOD | md5      | See hashlib.algorithms_guaranteed | One of hashlib.algorithms_guaranteed to perform the hash compare.    |
=====================================================================================================================================================================================================
```
 ### Execution
 From the command line:
 - When compareWithWsGit = True
 `python ws_version_checker.py -f $fileDir -n $fileName -g $compareWithWsGit`
 - When compareWithWsGit = False
 `python ws_version_checker.py -f $fileDir -n $fileName -g $compareWithWsGit -m $comparedHashMethod`
 
 Using a config file:
 - `python ws_version_checker.py -c / --configFile <CONFIG_FILE>`
 
 Environment Variables:
 - A parameter name as defined in the configuration file converted to upper case with underscore (`_`) separators and **WSVC**_ prefix added.
 - For example the `fileName` parameter can be set using the `WSVC_FILE_NAME` environment variable.
 - In case an environment variable exists , it will overrun any value which exists for the matching parmter in the command line  / configuration file.
   
 
### Author
WhiteSource Software ©
