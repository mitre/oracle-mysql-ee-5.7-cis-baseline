control "5.6" do
  title "Ensure 'create_user_priv' Is Not Set to 'Y' for Non-Administrative Users (Scored)"
  desc  "The CREATE USER privilege governs the right of a given user to add or remove users, change existing users' names, or revoke existing users' privileges."
  impact 0.5
  tag "severity": "medium"  
  tag "cis_id": "5.6"
  tag "cis_level": 1
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "audit text": "Execute the following SQL statement to audit this setting:
    SELECT user, host FROM mysql.user WHERE Create_user_priv = 'Y';
  Ensure only administrative users are returned in the result set."
  tag "fix": "Perform the following steps to remediate this setting:
    1. Enumerate the non-administrative users found in the result set of the audit procedure
    2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user):
    REVOKE CREATE USER ON *.* FROM '<user>';"
  query = %(select user from mysql.user where Create_user_priv = 'Y';)
 
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
  mysql_user_create_user_priv = sql_session.query(query).stdout.strip.split("\n") 


  if !mysql_user_create_user_priv.empty?
    mysql_user_create_user_priv.each do |user|
      describe "The mysql user: #{user} with create_user_priv" do
        subject { user }
        it { should be_in attribute('mysql_administrative_users') }
      end
    end
  end
  if mysql_user_create_user_priv.empty?
    impact 0.0
    desc 'There are no mysql users with create_user_priv allowed, therefore this control is not applicable'
    describe 'There are no mysql users with create_user_priv allowed, therefore this control is not applicable' do
      skip 'There are no mysql users with create_user_priv allowed, therefore this control is not applicable'
    end
  end
end