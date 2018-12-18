control "9.4" do
  title "Ensure 'super_priv' Is Not Set to 'Y' for Replication Users (Scored)"
  desc  "The SUPER privilege found in the mysql.user table governs the use of a variety of MySQL features. 
  These features include, CHANGE MASTER TO, KILL, mysqladmin kill option, PURGE BINARY LOGS, SET GLOBAL,
  mysqladmin debug option, logging control, and more."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "9.4"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Execute the following SQL statement to audit this setting:
    select user, host from mysql.user where user='repl' and Super_priv = 'Y';
  No rows should be returned.
  NOTE: Substitute your replication user's name for repl in the above query."
  tag "fix": "Execute the following steps to remediate this setting:
  1. Enumerate the replication users found in the result set of the audit procedure
  2. For each replication user, issue the following SQL statement (replace 'repl' with
  your replication user's name):
  REVOKE SUPER ON *.* FROM 'repl'"
  tag "Default Value": ""

  
end
