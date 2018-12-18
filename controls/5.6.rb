control "5.6" do
  title "Ensure 'create_user_priv' Is Not Set to 'Y' for Non-Administrative Users (Scored)"
  desc  "The CREATE USER privilege governs the right of a given user to add or remove users, change existing users' names, or revoke existing users' privileges."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "5.6"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Execute the following SQL statement to audit this setting:
    SELECT user, host FROM mysql.user WHERE Create_user_priv = 'Y';
  Ensure only administrative users are returned in the result set."
  tag "fix": "Perform the following steps to remediate this setting:
    1. Enumerate the non-administrative users found in the result set of the audit procedure
    2. For each user, issue the following SQL statement (replace "<user>" with the non- administrative user):
    REVOKE CREATE USER ON *.* FROM '<user>';"
  tag "Default Value": ""

  
end