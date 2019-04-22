control '5.5' do
  title " Ensure 'shutdown_priv' Is Not Set to 'Y' for Non-Administrative Users (Scored)"
  desc  "The SHUTDOWN privilege simply enables use of the shutdown option to the mysqladmin command,
   which allows a user with the SHUTDOWN privilege the ability to shut down the MySQL server."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '5.5'
  tag "cis_level": 1
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "Execute the following SQL statement to audit this setting:
      SELECT user, host FROM mysql.user WHERE Shutdown_priv = 'Y';
  Ensure only administrative users are returned in the result set."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Enumerate the non-administrative users found in the result set of the audit procedure
  2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user):
    REVOKE SHUTDOWN ON *.* FROM '<user>';"
  query = %{select user from mysql.user where Shutdown_priv = 'Y';}

  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))
  mysql_user_shutdown_priv = sql_session.query(query).stdout.strip.split("\n")

  if !mysql_user_shutdown_priv.empty?
    mysql_user_shutdown_priv.each do |user|
      describe "The mysql user: #{user} with shutdown_priv" do
        subject { user }
        it { should be_in attribute('mysql_administrative_users') }
      end
    end
  end
  if mysql_user_shutdown_priv.empty?
    impact 0.0
    describe 'There are no mysql users with shutdown_priv allowed, therefore this control is not applicable' do
      skip 'There are no mysql users with shutdown_priv allowed, therefore this control is not applicable'
    end
  end
end
