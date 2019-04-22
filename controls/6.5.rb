control '6.5' do
  title "Ensure audit_log_connection_policy is not set to 'NONE' (Scored)"
  desc  'The audit_log_connection_policy variable controls how the audit plugin writes connection events to the audit log file.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.5'
  tag "cis_level": 1
  tag "nist": ['AU-2', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "To assess this recommendation, execute the following SQL statement:
    show variables like '%audit_log_connection_policy%';
  Ensure the value is set to either ERRORS or ALL.
  "
  tag "fix": "To remediate this configuration setting, execute one of the following SQL statements:
    set global audit_log_connection_policy = ERRORS
      Or
    set global audit_log_connection_policy = ALL
  To ensure this remediation remains indefinite for the life of the MySQL Server, set audit_log_connection_policy in the server's assigned MySQL configuration file (usually named my.cnf, but not always)."
  tag "Default Value": 'The default value for audit_log_connection_policy is ALL.'

  query = %{SELECT @@audit_log_connection_policy;}
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  audit_log_connection_policy = sql_session.query(query).stdout.strip

  describe.one do
    describe 'The MySQL audit_log_connection_policy' do
      subject { audit_log_connection_policy }
      it { should cmp 'ALL' }
    end
    describe 'The MySQL audit_log_connection_policy' do
      subject { audit_log_connection_policy }
      it { should cmp 'ERRORS' }
    end
  end
end
