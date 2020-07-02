# iker
Welcome to iker!

# Introduction
iker is an ike-scan wrapper of iker.py initially written by Julio Gomez Ortega (JGO@portcullis-security.com) and archived by (isaudits/scripts). The script was updated to include the following:
* All known IKE encryption, hash, and key exchange algorithms in addition to authentication methods found in RFCs and open source IKE code
* Clear text/XML output with logging and explanations for each weak configuration found
* A base scan which scans all industry accepted weak configurations
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
