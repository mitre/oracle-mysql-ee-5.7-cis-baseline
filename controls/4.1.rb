control "4.1" do
  title "4.1 Ensure Latest Security Patches Are Applied (Not Scored)"
  desc  "Periodically, updates to MySQL server are released to resolve bugs, mitigate vulnerabilities, and provide new features. 
  It is recommended that MySQL installations are up to date with the latest security updates"
  impact 0.0 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "4.1"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "
  Execute the following SQL statement to identify the MySQL server version:
    SHOW VARIABLES WHERE Variable_name LIKE 'version';
  Now compare the version with the security announcements from Oracle and/or the OS if the OS packages are used"
  tag "fix": "Install the latest patches for your version or upgrade to the latest version"
  tag "Default Value": ""

  
end
