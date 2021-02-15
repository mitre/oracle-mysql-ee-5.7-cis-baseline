# frozen_string_literal: true

control '6.6' do
  title 'Ensure audit_log_exclude_accounts is set to NULL (Scored)'
  desc  'The audit_log_exclude_accounts variable enables the administrator to set accounts for which events will not be logged in the audit log.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.6'
  tag "cis_level": 1
  tag "nist": %w[AU-2 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "To assess this recommendation, execute the following SQL statement:
    SHOW VARIABLES LIKE '%audit_log_exclude_accounts%';
  Ensure the resulting audit_log_exclude_accounts value is NULL."
  tag "fix": "To remediate this configuration setting, execute the following SQL statement
    SET GLOBAL audit_log_exclude_accounts = NULL
  Or set audit_log_exclude_accounts=NULL in my.cnf."
  tag "Default Value": 'audit_log_exclude_accounts is set to NULL by default'

  audit_log_exclude_accounts = mysql_session(
    input('user'), input('password'), input('host'), input('port')
  ).query("SELECT @@audit_log_exclude_accounts;").stdout.strip
  puts "audit_log_exclude_accounts = #{audit_log_exclude_accounts}"
  describe 'The MySQL audit_log_exclude_accounts' do
    subject { audit_log_exclude_accounts }
    it { should eq 'NULL' }
  end
end
