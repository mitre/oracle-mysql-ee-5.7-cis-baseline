# frozen_string_literal: true
control '6.5' do
  title " Ensure 'log-raw' Is Set to 'OFF' (Scored)"
  desc "The log-raw MySQL option determines whether passwords are rewritten by the server so as not to appear in log files as plain text. If log-raw is enabled,
        then passwords are written to the various log files (general query log, slow query log, and binary log) in plain text."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.5'
  tag "cis_level": 1
  tag "nist": %w[AU-2 Rev_4]
  tag "Audit:
      Perform the following actions to assess this recommendation:
      • Open the MySQL configuration file (my.cnf)
      • Ensure the log-raw entry is present
      • Ensure the log-raw entry is set to OFF"
  tag "Remediation:
      Perform the following actions to remediate this setting:
      • Open the MySQL configuration file (my.cnf)
      • Find the log-raw entry and set it as follows log-raw = OFF"
  tag "Default Value: OFF"
  log_raw = mysql_session(input('user'), input('password'), input('host')).query("select @@log_raw").stdout.strip
  puts "6.5 select @@log_raw = #{log_raw} "
  describe 'The MYSQL log_raw entry should be set to OFF' do
    subject { log_raw }
    it {should eq '0'}
  end
end
