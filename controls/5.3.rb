control "5.3" do
  title "Ensure 'process_priv' Is Not Set to 'Y' for Non-Administrative Users (Scored)"
  desc  "The PROCESS privilege found in the mysql.user table determines whether a given user can see statement execution information for all sessions."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "5.3"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 2
  tag "audit text": "Execute the following SQL statement to audit this setting:
    select user, host from mysql.user where Process_priv = 'Y';
  Ensure only administrative users are returned in the result set."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Enumerate the non-administrative users found in the result set of the audit procedure
  2. For each user, issue the following SQL statement (replace "<user>" with the non- administrative user:
    REVOKE PROCESS ON *.* FROM '<user>';"
  tag "Default Value": ""

  
end