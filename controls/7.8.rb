control '7.8' do
  title 'Ensure No Anonymous Accounts Exist (Scored)'
  desc  "Anonymous accounts are users with empty usernames (''). Anonymous accounts have no passwords, so anyone can use them to connect to the MySQL server."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '7.8'
  tag "cis_level": 1
  tag "cis_level": 2
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "Profile Applicability": 'Level 2 - MySQL RDBMS'
  tag "audit text": "Execute the following SQL query to identify anonymous accounts:
  SELECT user,host FROM mysql.user WHERE user = '';
  The above query will return zero rows if no anonymous accounts are present."
  tag "fix": "Perform the following actions to remediate this setting:
  1. Enumerate the anonymous users returned from executing the audit procedure
  2. For each anonymous user, DROP or assign them a name
  NOTE: As an alternative, you may execute the mysql_secure_installation utility."
  tag "Default Value": "Using the standard installation script, mysql_install_db, it will create two anonymous accounts:
  one for the host 'localhost' and the other for the network interface's IP address."

  query = %{SELECT user,host FROM mysql.user WHERE user = '';}
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  anonymous_accounts = sql_session.query(query).stdout.strip

  describe 'The MySQL anonymous accounts that exist' do
    subject { anonymous_accounts }
    it { should be_empty }
  end
end
