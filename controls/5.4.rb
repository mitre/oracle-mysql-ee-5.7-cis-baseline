control "5.4" do
  title "Ensure 'super_priv' Is Not Set to 'Y' for Non-Administrative Users (Scored)"
  desc  "The SUPER privilege found in the mysql.user table governs the use of a variety of MySQL features. 
  These features include, CHANGE MASTER TO, KILL, mysql admin kill option, PURGE BINARY LOGS, SET GLOBAL, mysqladmin debug option, logging control, and more."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "5.4"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Execute the following SQL statement to audit this setting:
    select user, host from mysql.user where Super_priv = 'Y';
  Ensure only administrative users are returned in the result set."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Enumerate the non-administrative users found in the result set of the audit procedure
  2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user:
    REVOKE SUPER ON *.* FROM '<user>';"
  tag "Default Value": ""

  
end