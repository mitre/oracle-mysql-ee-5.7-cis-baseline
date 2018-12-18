control "7.5" do
  title "Ensure Passwords Are Set for All MySQL Accounts (Scored)"
  desc  "Blank passwords allow a user to login without using a password."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "7.5"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "cis_level": 2
  tag "audit text": "Execute the following SQL query to determine if any users have a blank password:
      SELECT User,host
      FROM mysql.user
      WHERE (plugin IN('mysql_native_password', 'mysql_old_password')
        AND (LENGTH(Password) = 0
        OR Password IS NULL))
        OR (plugin='sha256_password' AND LENGTH(authentication_string) = 0);
  No rows will be returned if all accounts have a password set."
  tag "fix": "or each row returned from the audit procedure, set a password for the given user using the following statement (as an example):
  SET PASSWORD FOR <user>@'<host>' = PASSWORD('<clear password>')
  NOTE: Replace <user>, <host>, and <clear password> with appropriate values."
  tag "Default Value": ""

  
end
