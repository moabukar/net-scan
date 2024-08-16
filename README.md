# Net scanning tool 

## Usage

- Make sure to have nmap installed on your machine & python-nmap

- Run with sudo `sudo python3 net-scan.py`

Note: # nmap is needed as well. On macOS: brew install nmap, pip install python-nmap (as sudo for OS fingerprinting)

Sample output:

```bash
> sudo python3 net-scan.py
------------------------
subnet:10.100.100.0/24
live hosts on subnet:['10.100.100.3', '10.100.100.100', '10.100.100.150']
```
