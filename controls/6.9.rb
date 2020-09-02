control '6.9' do
  title 'Ensure audit_log_policy is set to log logins and connections (Scored)'
  desc  'With the audit_log_policy setting the amount of information which is sent to the audit log is controlled. It must be set to log logins and connections.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.9'
  tag "cis_level": 2
  tag "nist": ['AU-2', 'Rev_4']
  tag "Profile Applicability": 'Level 2 - MySQL RDBMS'
  tag "check": "SHOW GLOBAL VARIABLES LIKE 'audit_log_policy';
  The result must be ALL."
  tag "fix": "Set audit_log_policy='ALL' in the MySQL configuration file and activate the setting by restarting the server or executing SET GLOBAL audit_log_policy='ALL';"
  tag "Default Value": 'ALL'

  query = %{SELECT @@audit_log_include_accounts;}
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  audit_log_policy = sql_session.query(query).stdout.strip

  describe 'The MySQL audit_log_policy' do
    subject { audit_log_policy }
    it { should cmp 'ALL' }
  end
end
