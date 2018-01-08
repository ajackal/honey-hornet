# Honey Hornet
port scanner &amp; login credential tester

## honeyhornet.py
Use the `config.yml` file to set how Honey Hornet will run:
  1) _port scanner_ or _credential checker_ mode
  2) ports to scan
  3) usernames and passwords to check
  4) location of the targets list to use
  5) output file types:
        - standard logs (default)
        - JSON
        - csv
  
### Port Scanner Mode
This will scan the IP addresses listed in the target file and check for open ports defined in the `config.yml` configuration file.

### Credential Checker Mode
This mode will check for valid login credentials that are defined in the `config.yml` configuration file, after running in _Port Scanner Mode_.

    Proctols currently supported:
    1. FTP
    2. SSH
    3. Telnet
    4. HTTP-XML authentication
        - uses an XML-file to POST credentials to web portal.  
        
### Example Usage
`python honeyhornet.py` will use the default config file `config.yml` <br>
`python honeyhornet.py --config custom.yml` will use a custom defined config file, in this case `custom.yml`