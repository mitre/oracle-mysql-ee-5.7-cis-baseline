# frozen_string_literal: true
control '6.4' do
  title "Ensure Audit Logging Is Enabled (Not Scored)"
  desc "Description:Audit logging is not really included in the Community Edition of MySQL - only the general log. Using the general log is possible, but not practical,
        because it grows quickly and has an adverse impact on server performance.
        Nevertheless, enabling audit logging is an important consideration for a production environment, and third-party tools do exist to help with this. Enable audit logging for
          • Interactive user sessions
          • Application sessions (optional)"
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.4'
  tag "cis_level": 2
  tag "nist": %w[AU-2 Rev_4]
  tag "Profile Applicability:Level 2 - MySQL RDBMS"
  tag "Audit Text: Verify that a third-party tool is installed and configured to enable logging for interactive user sessions and (optionally) applications sessions. "
  tag "Remediation:
      Acquire a third-party MySQL logging solution as available from a variety of sources including, but not necessarily limited to, the following:
      • The General Query Log
      • MySQL Enterprise Audit
      • MariaDB Audit Plugin for MySQL
      • McAfee MySQL Audit"

  audit_log_file = mysql_session(
              input('user'), input('password'), input('host')
              ).query("select @@audit_log_file;").stdout.strip
  puts "Control 6.4 \t audit_log_file = #{audit_log_file} "
  describe 'The MySQL audit_log_file location' do
    subject { audit_log_file }
    it { should_not be_empty }
  end
end
