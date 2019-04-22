control "5.7" do
  title "Ensure 'grant_priv' Is Not Set to 'Y' for Non-Administrative Users (Scored)"
  desc  "The GRANT OPTION privilege exists in different contexts (mysql.user, mysql.db) for the purpose of governing the ability of a privileged user to manipulate the privileges of other users."
  impact 0.5 
  tag "severity": "medium" 
  tag "cis_id": "5.7"
  tag "cis_level": 1
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "audit text": "Execute the following SQL statements to audit this setting:
      SELECT user, host FROM mysql.user WHERE Grant_priv = 'Y'; 
      SELECT user, host FROM mysql.db WHERE Grant_priv = 'Y';
  Ensure only administrative users are returned in the result set."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Enumerate the non-administrative users found in the result sets of the audit procedure
  2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user:
    REVOKE GRANT OPTION ON *.* FROM <user>;"

  mysql_user_query = %(SELECT user FROM mysql.user WHERE Grant_priv = 'Y';)
  mysql_user_db_query = %(SELECT user FROM mysql.db WHERE Grant_priv = 'Y';)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
  mysql_user_privs = sql_session.query(mysql_user_query).stdout.strip.split("\n") 
  mysql_user_db_privs = sql_session.query(mysql_user_db_query).stdout.strip.split("\n") 

  if !mysql_user_privs.empty?
    mysql_user_privs.each do |user|
      describe "The mysql user: #{user} with grant_priv access in the mysql.user table" do
        subject { user }
        it { should be_in attribute('mysql_administrative_users') }
      end
    end
  end
  if !mysql_user_db_privs.empty?
    mysql_user_db_privs.each do |user|
      describe "The mysql user: #{user} with grant_priv access in the mysql.db table" do
        subject { user }
        it { should be_in attribute('mysql_administrative_users') }
      end
    end
  end

  if mysql_user_privs.empty? && mysql_user_db_privs.empty?
    impact 0.0
    describe 'There are no mysql users configured with grant_priv access, therefore this control is not applicable' do
      skip 'There are no mysql users configured with grant_priv access, therefore this control is not applicable'
    end
  end
  
end