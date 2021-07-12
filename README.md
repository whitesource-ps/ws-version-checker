![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/release/whitesource-ps/ws-version-checker)](https://github.com/whitesource-ps/ws-version-checker/releases/latest)   
[![WS Version Checker Build and Publish](https://github.com/whitesource-ps/ws-version-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-version-checker/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)

# WhiteSource Version-Checker
The script enables checking the WhiteSource artifacts , validate whether there is a new version and update it accordingly.
### Supported artifacts 
- [WhiteSource Unified Agent](https://whitesource.atlassian.net/wiki/spaces/WD/pages/804814917/Unified+Agent+Overview).

### How to use the script
- Run on your local machine where the artifact is stored.
- Run as part of your CI process , prior of using one of the supported artifacts.

### What does the script do?
The script checks the artifact version by one of the following :
1. Compare of the local version file hash value (based on [hashlib.algorithms_guaranteed](https://github.com/python/cpython/blob/main/Lib/hashlib.py)) with the latest version from WhiteSource.
2. Compare of the local version file semantic versioning with the WhiteSource artifact GitHub repo latest release link - [for example - Unified Agent](https://github.com/whitesource/unified-agent-distribution/releases) .

### Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

### Prerequisites
- Python 3.6 or above

### Installation
1. Download and unzip **ws-version-checker.zip**.
2. From the command line, navigate to the ws-version-checker directory and install the package:  
   `pip install -r requirements.txt`. 
3. Edit the **params.config** file and update the relevant parameters (see the configuration parameters below) or
   use a cmd line for running.
    
### Configuration Parameters
```
============================================================================================================================================================================
| config file            | cli                        | Default  | Optional values                  | Description                                                           |
============================================================================================================================================================================
| fileDir                | -f,  --fileDir             |          |                                   | The file directory path.                                             |
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| fileName               | -n,  --fileName            |          |                                   | The name of the file to be checked by the tool.                      |
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| comparedHashMethod     | -m,  --comparedHashMethod  | md5      | See hashlib.algorithms_guaranteed | One of hashlib.algorithms_guaranteed to perform the hash compare.    |
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| compareWithWsGit       | -g,  --compareWithWsGit    | False    | True / False                      | If True -compared with git version ,if false use comparedHashMethod. |
============================================================================================================================================================================
```
 ### Execution
 From the command line:
 - `python ws-version-checker.py -f $fileDir -n $fileName -m $comparedHashMethod -g $compareWithWsGit`
 
 Using a config file:
 - `python ws-copy-policy.py -c / --configFile <CONFIG_FILE>`
 
### Author
WhiteSource Software ©