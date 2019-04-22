control '6.8' do
  title 'Ensure audit_log_policy is set to log logins (Scored)'
  desc  'With the audit_log_policy setting the amount of information which is sent to the audit log is controlled. It must be set to log logins.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.8'
  tag "cis_level": 1
  tag "nist": ['AU-2', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "SHOW GLOBAL VARIABLES LIKE 'audit_log_policy';
  The result must be LOGINS or ALL."
  tag "fix": "Set audit_log_policy='ALL' or audit_log_policy='LOGINS' in the MySQL configuration file and activate the setting by restarting the server or executing
   SET GLOBAL audit_log_policy='ALL'; or SET GLOBAL audit_log_policy='LOGINS';"
  tag "Default Value": 'ALL'

  query = %{SELECT @@audit_log_policy;}
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  audit_log_policy = sql_session.query(query).stdout.strip

  describe.one do
    describe 'The MySQL audit_log_policy' do
      subject { audit_log_policy }
      it { should cmp 'ALL' }
    end
    describe 'The MySQL audit_log_policy' do
      subject { audit_log_policyy }
      it { should cmp 'LOGINS' }
    end
  end
end
