control '9.5' do
  title 'Ensure No Replication Users Have Wildcard Hostnames (Scored)'
  desc  "MySQL can make use of host wildcards when granting permissions to users on specific databases. For example, you may grant a given privilege to '<user>'@'%'."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '1.1'
  tag "cis_level": 1
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "Execute the following SQL statement to assess this recommendation:
    SELECT user, host FROM mysql.user WHERE user='repl' AND host = '%';
  Ensure no rows are returned."
  tag "fix": "Perform the following actions to remediate this setting:
  1. Enumerate all users returned after running the audit procedure
  2. Either ALTER the user's host to be specific or DROP the user"
  query = "SELECT user, host FROM mysql.user WHERE user='repl' AND host = '%';"
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))
  wildcard_hostname = sql_session.query(query).stdout.strip
  describe 'The replication users with the super_priv not set to Y' do
    subject { wildcard_hostname }
    it { should be_empty }
  end
end
