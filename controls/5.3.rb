control '5.3' do
  title "Ensure 'process_priv' Is Not Set to 'Y' for Non-Administrative Users (Scored)"
  desc  'The PROCESS privilege found in the mysql.user table determines whether a given user can see statement execution information for all sessions.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '5.3'
  tag "cis_level": 2
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": 'Level 2 - MySQL RDBMS'
  tag "check": "Execute the following SQL statement to audit this setting:
    select user, host from mysql.user where Process_priv = 'Y';
  Ensure only administrative users are returned in the result set."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Enumerate the non-administrative users found in the result set of the audit procedure
  2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user:
    REVOKE PROCESS ON *.* FROM '<user>';"
  query = %{select user from mysql.user where Process_priv = 'Y';}

  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))
  mysql_user_process_priv = sql_session.query(query).stdout.strip.split("\n")

  if !mysql_user_process_priv.empty?
    mysql_user_process_priv.each do |user|
      describe "The mysql user: #{user} with process_priv" do
        subject { user }
        it { should be_in attribute('mysql_administrative_users') }
      end
    end
  end
  if mysql_user_process_priv.empty?
    impact 0.0
    describe 'There are no mysql users with process_priv allowed, therefore this control is not applicable' do
      skip 'There are no mysql users with process_priv allowed, therefore this control is not applicable'
    end
  end
end
