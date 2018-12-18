control "5.1" do
  title "Ensure Only Administrative Users Have Full Database Access (Scored)"
  desc  "The mysql.user and mysql.db tables list a variety of privileges that can be granted (or denied) to MySQL users. 
  Some of the privileges of concern include: Select_priv, Insert_priv,Update_priv,Delete_priv,Drop_priv,and so on. 
  Typically,theseprivileges should not be available to every MySQL user and often are reserved for administrative use only."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "5.1"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "
  Execute the following SQL statement(s) to assess this recommendation:
 
    SELECT user, host
    FROM mysql.user
    WHERE (Select_priv = 'Y')
    OR (Insert_priv = 'Y') OR (Update_priv = 'Y') OR (Delete_priv = 'Y') OR (Create_priv = 'Y') OR (Drop_priv = 'Y');
    SELECT user, host FROM mysql.db WHERE db = 'mysql'
    AND ((Select_priv = 'Y') OR (Insert_priv = 'Y') OR (Update_priv = 'Y') OR (Delete_priv = 'Y') OR (Create_priv = 'Y')
    OR (Drop_priv = 'Y'));
  Ensure all users returned are administrative users."
  tag "fix": "Perform the following actions to remediate this setting:
  1. Enumerate non-administrative users resulting from the audit procedure
  2. For each non-administrative user, use the REVOKE statement to remove privileges as
  appropriate"
  tag "Default Value": ""

  
end