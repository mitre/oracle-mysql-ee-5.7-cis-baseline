control '7.5' do
  title 'Ensure Passwords Are Set for All MySQL Accounts (Scored)'
  desc  'Blank passwords allow a user to login without using a password.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '7.5'
  tag "cis_level": 1
  tag "cis_level": 2
  tag "nist": ['IA-5(1)', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "Profile Applicability": 'Level 2 - MySQL RDBMS'
  tag "check": "Execute the following SQL query to determine if any users have a blank password:
      SELECT User,host
      FROM mysql.user
      WHERE (plugin IN('mysql_native_password', 'mysql_old_password')
        AND (LENGTH(authentication_string) = 0
        OR authentication_string IS NULL))
        OR (plugin='sha256_password' AND LENGTH(authentication_string) = 0);
  No rows will be returned if all accounts have a password set."
  tag "fix": "or each row returned from the audit procedure, set a password for the given user using the following statement (as an example):
  SET PASSWORD FOR <user>@'<host>' = PASSWORD('<clear password>')
  NOTE: Replace <user>, <host>, and <clear password> with appropriate values."

  query = %{SELECT User,host
      FROM mysql.user
      WHERE (plugin IN('mysql_native_password', 'mysql_old_password')
        AND (LENGTH(authentication_string) = 0
        OR authentication_string IS NULL))
        OR (plugin='sha256_password' AND LENGTH(authentication_string) = 0);}
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))
  users_with_blank_passwords = sql_session.query(query).stdout.strip

  describe 'The MySQL users with blank passwords' do
    subject { users_with_blank_passwords }
    it { should be_empty }
  end
end
