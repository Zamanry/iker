# iker
Welcome to iker!

# Introduction
iker is an ike-scan wrapper of iker.py initially written by Julio Gomez Ortega (JGO@portcullis-security.com) and archived by (isaudits/scripts). The script was forked and updated to include the following supported features:
## Supported Features
* Discovers IKEv1 and v2 services
* Extracts vendor IDs (VID)
* Guesses the vendor implementation (backoff)
* Enumerates supported transforms in main
* Checks for aggressive mode support and enumerates supported transforms
* Enumerates valid group names(IDs) in aggressive mode
* Parses scan results to identify configuration risks based on industry best-practices
* Outputs scan to text and XML file formats
* Python2+ and Python3+ support
# Installation
The following steps will describe how to install ike-scan and iker:
1. sudo apt update
2. sudo apt install ike-scan -y
3. git clone https://github.com/Zamanry/iker.git
4. cd ./iker
# Usage
The following steps will describe how to use iker:
## Single host with base scan
1. sudo ./iker.py #.#.#.#
## Multiple hosts with all algorithms
1. sudo ./iker.py -i <hosts.txt> --fullalgs
## Multiple hosts with logging
1. sudo ./iker.py -i <hosts.txt> -o <output.txt> -x <output.xml>
## Multiple hosts with specific key exchange groups
1. sudo ./iker.py -i <hosts.txt> --kegroups="1 2 3 4 5"
