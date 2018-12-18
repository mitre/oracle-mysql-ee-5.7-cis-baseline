control "4.8" do
  title "Ensure 'secure_file_priv' Is Not Empty (Scored)"
  desc  "The secure_file_priv option restricts to paths used by LOAD DATA INFILE or SELECT local_file. 
  It is recommended that this option be set to a file system location that contains only resources expected to be loaded by MySQL."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "4.8"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Execute the following SQL statement and ensure one row is returned:
    SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv' AND Value<>'';
  Note: The Value should contain a valid path."
  tag "fix": "Add the following line to the [mysqld] section of the MySQL configuration file and restart the MySQL service:
    secure_file_priv=<path_to_load_directory>
  "
  tag "Default Value": "No value set."

  
end