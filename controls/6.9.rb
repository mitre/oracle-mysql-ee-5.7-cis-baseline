# frozen_string_literal: true

control '6.9' do
  title 'Ensure audit_log_policy is set to log logins and connections (Scored)'
  desc  'With the audit_log_policy setting the amount of information which is sent to the audit log is controlled. It must be set to log logins and connections.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.9'
  tag "cis_level": 2
  tag "nist": %w[AU-2 Rev_4]
  tag "Profile Applicability": 'Level 2 - MySQL RDBMS'
  tag "audit text": "SHOW GLOBAL VARIABLES LIKE 'audit_log_policy';
  The result must be ALL."
  tag "fix": "Set audit_log_policy='ALL' in the MySQL configuration file and activate the setting by restarting the server or executing SET GLOBAL audit_log_policy='ALL';"
  tag "Default Value": 'ALL'

  audit_log_policy = mysql_session(
    input('user'), input('password'), input('host'), input('port')
  ).query("SELECT @@audit_log_include_accounts;").stdout.strip
  puts "SELECT @@audit_log_include_accounts; = #{audit_log_policy}"
  describe 'The MySQL audit_log_policy' do
    subject { audit_log_policy }
    it { should eq 'ALL' }
  end
end
