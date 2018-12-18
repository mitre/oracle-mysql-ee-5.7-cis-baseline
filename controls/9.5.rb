control "9.5" do
  title "Ensure No Replication Users Have Wildcard Hostnames (Scored)"
  desc  "MySQL can make use of host wildcards when granting permissions to users on specific databases. For example, you may grant a given privilege to '<user>'@'%'."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "1.1"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Execute the following SQL statement to assess this recommendation:
    SELECT user, host FROM mysql.user WHERE user='repl' AND host = '%';
  Ensure no rows are returned."
  tag "fix": "Perform the following actions to remediate this setting:
  1. Enumerate all users returned after running the audit procedure
  2. Either ALTER the user's host to be specific or DROP the user"
  tag "Default Value": ""

  
end
