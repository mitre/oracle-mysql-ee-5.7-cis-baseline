control "9.2" do
  title "Ensure 'MASTER_SSL_VERIFY_SERVER_CERT' Is Set to 'YES' or '1' (Scored)"
  desc  "In the MySQL slave context the setting MASTER_SSL_VERIFY_SERVER_CERT indicates whether the slave should verify the master's certificate. 
  This configuration item may be set to Yes or No, and unless SSL has been enabled on the slave, the value will be ignored."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "9.2"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "To assess this recommendation, issue the following statement:
  select ssl_verify_server_cert from mysql.slave_master_info;
  Verify the value of ssl_verify_server_cert is 1."
  tag "fix": "To remediate this setting you must use the CHANGE MASTER TO command.
              STOP SLAVE; -- required if replication was already running 
              CHANGE MASTER TO MASTER_SSL_VERIFY_SERVER_CERT=1;
              START SLAVE; -- required if you want to restart replication"
  tag "Default Value": ""

  
end
