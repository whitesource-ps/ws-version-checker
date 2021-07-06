![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/release/whitesource-ps/wss-template.svg)](https://github.com/whitesource-ps/wss-template/releases/latest)  
[![WS Version Checker Build and Publish](https://github.com/whitesource-ps/ws-version-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-version-checker/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)

# WhiteSource Version-Checker tool
The script allows checking the WhiteSource artifacts , validate whether there is a newer version and update it accordingly.
### Supported artifacts :
- WhiteSource Unified Agent.

### How to use the script
- Run on you local machine where the artifact stored.
- Run as part of your CI process , prior of using once of the supported artifacts.

### What does the script do?
The script checks the artifact version by one of the following :
1. compare of the local version file hash value with the latest version from WhiteSource site.
2. compare of the local version file semantic versioning with the WhiteSource GitHub latest release link.

### Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

### Prerequisites
- Python 3.5 or above

### Installation
1. Download and unzip **ws-version-checker.zip**.
2. From the command line, navigate to the ws-version-checker directory and install the package:  
   `pip install -r requirements.txt`. 
3. Edit the **params.config** file and update the relevant parameters (see the configuration parameters below) or
   use a cmd line for running.
    
### Configuration Parameters
```
==============================================================================================================================
| config file            | cli                       | Description                                                           |
==============================================================================================================================
| fileDir                | -f  --fileDir             | The file directory path.                                              |
------------------------------------------------------------------------------------------------------------------------------
| fileName               | -n  --fileName            | The name of the file to be checked by the tool.                       |
------------------------------------------------------------------------------------------------------------------------------
| comparedHashMethod     | -m  --comparedHashMethod  | One of hashlib.algorithms_guaranteed to perform the hash compare.     |
------------------------------------------------------------------------------------------------------------------------------
| compareWithWsGit       | -g  --compareWithWsGit    | If True -compared with git version ,if false use comparedHashMethod.  |
==============================================================================================================================
```
 ### Execution
 From the command line:
 - `python ws-version-checker.py -f $filerDir -n $fileName -m $ -g $compareWithWsGit`
 
 Using a config file:
 - `python ws-copy-policy.py <CONFIG_FILE>`
 
### Author
WhiteSource Software ©