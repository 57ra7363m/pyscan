README

Pyscan is a simple script written in an attempt to learn how to parse arguments in python scripts.  Currently it only utilizes nmap for scans, but will soon incorporate nikto, and potentially other scanning and vulnerability assessment frameworks.

Dependencies
python-nmap

Usage

python pyscan.py -t (hosts) -o '(scanning options)'

-h will display the help page
Note: Currently, the python-nmap library does not support xml outputs, except with work arounds.