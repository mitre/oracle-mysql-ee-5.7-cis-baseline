control "5.1" do
  title "Ensure Only Administrative Users Have Full Database Access (Scored)"
  desc  "The mysql.user and mysql.db tables list a variety of privileges that can be granted (or denied) to MySQL users. 
  Some of the privileges of concern include: Select_priv, Insert_priv,Update_priv,Delete_priv,Drop_priv,and so on. 
  Typically,these privileges should not be available to every MySQL user and often are reserved for administrative use only."
  impact 0.5 
  tag "severity": "medium" 
  tag "cis_id": "5.1"
  tag "cis_level": 1
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
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
  mysql_user_query = %(SELECT user
    FROM mysql.user
    WHERE (Select_priv = 'Y')
    OR (Insert_priv = 'Y') OR (Update_priv = 'Y') OR (Delete_priv = 'Y') OR (Create_priv = 'Y') OR (Drop_priv = 'Y');
    )
  mysql_user_db_query = %(SELECT user, host FROM mysql.db WHERE db = 'mysql'
    AND ((Select_priv = 'Y') OR (Insert_priv = 'Y') OR (Update_priv = 'Y') OR (Delete_priv = 'Y') OR (Create_priv = 'Y')
    OR (Drop_priv = 'Y'));
    )
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
  mysql_user_privs = sql_session.query(mysql_user_query).stdout.strip.split("\n") 
  mysql_user_db_privs = sql_session.query(mysql_user_db_query).stdout.strip.split("\n") 

  if !mysql_user_privs.empty?
    mysql_user_privs.each do |user|
      describe "The mysql user: #{user} with privilege access in the mysql.user table" do
        subject { user }
        it { should be_in attribute('mysql_administrative_users') }
      end
    end
  end
  if !mysql_user_db_privs.empty?
    mysql_user_db_privs.each do |user|
      describe "The mysql user: #{user} with privilege access in the mysql.db table" do
        subject { user }
        it { should be_in attribute('mysql_administrative_users') }
      end
    end
  end

  if mysql_user_privs.empty? && mysql_user_db_privs.empty?
    impact 0.0
    desc 'There are no mysql users configured with full database access, therefore this control is not applicable'
    describe 'There are no mysql users configured with full database access, therefore this control is not applicable' do
      skip 'There are no mysql users configured with full database access, therefore this control is not applicable'
    end
  end
end