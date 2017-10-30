# Honey Hornet
port scanner &amp; login credential tester

## honeyhornet.py
Use the `config.yml` file to set honeyhonet in either:
  1) port scanner mode
  2) credential checker mode
  
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