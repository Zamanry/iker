# iker
Welcome to iker!

# Introduction
iker is an ike-scan wrapper to simplify penetration testing of Internet Key Exchange (IKE) services and encourage stronger IKE implementations.
## Supported Features
The following features are supported:
* Discovers IKEv1 and v2 services
* Extracts vendor IDs (VID)
* Guesses the vendor implementation (backoff)
* Enumerates supported transforms in main
* Checks for aggressive mode support and enumerates supported transforms
* Enumerates valid group names(IDs) in aggressive mode
* Parses scan results to identify configuration risks based on industry best-practices
* Outputs scan to text and XML file formats
* Supports Python2+ and Python3+

A full list of the supported algorithms and authentication methods can be found here:
* https://github.com/Zamanry/iker/wiki/IKE-Parameters
# Requirements
iker requires ike-scan which can be obtained through its APT/YUM package manager respository or GitHub project:
1. `sudo apt update`
2. `sudo apt install ike-scan -y`

OR

1. Follow the instructions from https://github.com/royhills/ike-scan
# Installation
The following steps will describe how to install ike-scan and iker:
1. `git clone https://github.com/zamanry/iker.git`
2. `cd ./iker`
# Usage
The following steps will describe how to use iker:
## Single host with base scan
1. `sudo ./iker.py #.#.#.#`
## Multiple hosts with all algorithms
1. `sudo ./iker.py -i <hosts.txt> --fullalgs`
## Multiple hosts with logging
1. `sudo ./iker.py -i <hosts.txt> -o <output.txt> -x <output.xml>`
## Multiple hosts with specific key exchange groups
1. `sudo ./iker.py -i <hosts.txt> --kegroups="1 2 3 4 5"`
# Risk Criteria
Risk is dynamic to each system. iker's default scan scans only configurations with enough risk which need to be changed. The criteria to be considered a risk are:
* Weak encryption algorithms are those considered broken by industry standards or key length is less than 128 bits.
* Weak hash algorithms are those considered broken by industry standards.
* Weak key exchange groups are those considered broken by industry standards or modulus is less than 2048 bits.
* Weak authentication methods are those not using multifactor authentication or not requiring mutual authentication.
# Sources
This project would not exist if it weren't for the following people:
* Wrote by Julio Gomez Ortega (JGO@portcullis-security.com)
* Edited and archived by IS Audits and Consulting LLC (https://github.com/isaudits/scripts)
