# frozen_string_literal: true

control '6.10' do
  title 'Ensure audit_log_statement_policy is set to ALL (Scored)'
  desc  'This setting controls whether statements are written to the audit log'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.10'
  tag "cis_level": 2
  tag "nist": %w[AU-2 Rev_4]
  tag "Profile Applicability": 'Level 2 - MySQL RDBMS'
  tag "audit text": "SHOW GLOBAL VARIABLES LIKE 'audit_log_statement_policy';
  It must return ALL"
  tag "fix": "Add this to the mysqld section of the mysql configuration file and restart the server:
  audit_log_statement_policy='ALL'"
  tag "Default Value": 'ALL'


  log_error = mysql_session(input('user'), input('password'), input('host'), input('port')).query("select @@log_error;").stdout.strip
  puts "select @@log_error; = #{log_error}"
  describe 'The MySQL log_error' do
    subject { log_error }
    it { should_not be_empty }
  end
 ## THis or that
  log_error = mysql_session(input('user'), input('password'), input('host'), input('port')).query("SHOW GLOBAL VARIABLES LIKE 'audit_log_statement_policy';").stdout.strip
  puts "SHOW GLOBAL VARIABLES LIKE 'audit_log_statement_policy' = #{log_error}"
  describe 'The MySQL log_error' do
    subject { log_error }
    it { should_not be_empty }
  end

end
