control '6.11' do
  title 'Set audit_log_strategy to SYNCHRONOUS or SEMISYNCRONOUS (Scored)'
  desc  'The audit_log_strategy must be set to SYNCHRONOUS or SEMISYNCHRONOUS'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.11'
  tag "cis_level": 2
  tag "nist": ['AU-2', 'Rev_4']
  tag "Profile Applicability": 'Level 2 - MySQL RDBMS'
  tag "audit text": "To assess this recommendation, execute the following SQL statement:
    SHOW GLOBAL VARIABLES LIKE 'audit_log_strategy';
  The result should be SYNCHRONOUS or SEMISYNCHRONOUS"
  tag "fix": "To remediate this configuration:
  1. Open the MySQL configuration file (my.cnf)
  2. Navigate to the mysqld section of the configuration file
  3. Set audit_log_strategy='SEMISYNCHRONOUS' (or SYNCHRONOUS)
  "
  tag "Default Value": 'ASYNCHRONOUS'

  query = %{SHOW GLOBAL VARIABLES LIKE 'audit_log_strategy';}
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  audit_log_strategy = sql_session.query(query).stdout.strip

  describe.one do
    describe 'The MySQL audit_log_strategy variable' do
      subject { audit_log_strategy }
      it { should cmp 'SYNCHRONOUS' }
    end
    describe 'The MySQL audit_log_strategy variable' do
      subject { audit_log_strategy }
      it { should cmp 'SEMISYNCHRONOUS' }
    end
  end
end
