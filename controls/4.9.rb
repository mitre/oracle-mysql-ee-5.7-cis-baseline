control "4.9" do
  title ""
  desc  "When data changing statements are made (i.e. INSERT, UPDATE), MySQL can handle invalid or missing values differently depending on whether strict SQL mode is enabled. 
  When strict SQL mode is enabled, data may not be truncated or otherwise 'adjusted' to make the data changing statement work"
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "4.9"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 2
  tag "audit text": "To audit for this recommendation execute the following query:
    SHOW VARIABLES LIKE 'sql_mode';
  Ensure that STRICT_ALL_TABLES is in the list returned."
  tag "fix": "Perform the following actions to remediate this setting:
    1. Add STRICT_ALL_TABLES to the sql_mode in the server's configuration file"
  tag "Default Value": ""

  
end