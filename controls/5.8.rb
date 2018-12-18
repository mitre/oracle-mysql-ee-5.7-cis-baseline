control "5.8" do
  title "Ensure 'repl_slave_priv' Is Not Set to 'Y' for Non-Slave Users (Scored)"
  desc  "The REPLICATION SLAVE privilege governs whether a given user 
  (in the context of the master server) can request updates that have been made on the master server."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "5.8"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Execute the following SQL statement to audit this setting:
      SELECT user, host FROM mysql.user WHERE Repl_slave_priv = 'Y';
  Ensure only accounts designated for slave users are granted this privilege."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Enumerate the non-slave users found in the result set of the audit procedure
  2. For each user, issue the following SQL statement (replace '<user>'' with the non-slave user):
    REVOKE REPLICATION SLAVE ON *.* FROM <user>;
  Use the REVOKE statement to remove the SUPER privilege from users who shouldn't have it."
  tag "Default Value": ""

  
end