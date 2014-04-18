#CloudPassage Check For CVE Example

Version: *1.0*
<br />
Author: *Eric Hoffmann* - *ehoffmann@cloudpassage.com*

Users can use the provided example script to check for the presence of any individual CVE or list of CVEs. It uses the Halo API to get the details of the last scheduled or manually launched SVA scan for all active servers. It then checks for the presence of the provided CVE(s) in the scan findings.

##Requirements and Dependencies

To run, this script requires

* Ruby installed on the host that runs the script
* Ruby gems: oauth2, rest-client, json
* A read-only Halo API key/secret stored in a yaml file
* The location of the yaml file set as a ENV variable

##List of Files

* **check_for_cves.rb**  - Ruby script which leverages the Halo API to check for the presence of various CVEs
* **README.md**  -  This ReadMe file
* **LICENSE.txt**  -  License from CloudPassage

##Usage

1. Copy a read-only Halo API key/secret from the Halo Portal into a "dot" file ie ~/.halo
2. Set the location of the api-key file as a ENV variable called HALO_API_KEY_FILE
3. Execute the script

The format of ~/.halo
```
halo:
  key_id : XXXXXXXX
  secret_key : XXXXXXXXXXXXXXXXXXXXXXXXXXX
```

The additional variable in your ~/.bash_profile
```
HALO_API_KEY_FILE="/home/<your username>/.halo"
export HALO_API_KEY_FILE
```

How to excute the script
```
ruby check_for_cves.rb --cve 'CVE-2010-0624,CVE-2011-4623'
ip-10-123-254-12, 53.215.74.1, centos,6.5, cpio.x86_64, 2.10-11.el6_3, CVE-2010-0624
ip-10-10-254-13, 54.192.200.254, centos,6.2, cpio.x86_64, 2.10-11.el6_3, CVE-2010-0624
ip-10-10-254-13, 54.192.200.254, centos,6.2, rsyslog.x86_64, 4.6.2-12.el6, CVE-2011-4623
Checked 2 servers for CVE-2010-0624,CVE-2011-4623
```
