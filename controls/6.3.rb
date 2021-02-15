

control '6.3' do
  title "Ensure 'log_error_verbosity' Is Not Set to '1'"
  desc  "The log_error_verbosity system variable provides additional information to the MySQL log. A value of 1 enables logging of error messages.
   value of 2 enables logging of error and warning messages, and a value of 3 enables logging of error, warning and note messages."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.3'
  tag "cis_level": 2
  tag "nist": %w[SC-2 Rev_4]
  tag "Profile Applicability: Level 2 - MySQL RDBMS"

  tag "Audit Text: Execute the following SQL statement to assess this recommendation:
      SHOW GLOBAL VARIABLES LIKE 'log_error_verbosity';"
  tag "Ensure the Value returned equals 2 or 3."
  tag "Fix: Remediation:
      Perform the following actions to remediate this setting:
      • Open the MySQL configuration file (my.cnf)
      • Ensure the following line is found in the mysqld section"
  tag "Default Value:
      The option is error+warning (2) by default."

  log_error_verbosity = mysql_session(input('user'), input('password'), input('host')).query("select @@log_error_verbosity;").stdout.strip
  describe.one do
    puts "Control 6.3 log_warnings = #{log_error_verbosity;}"
    describe 'The MySQL log_warnings' do
      subject { log_error_verbosity; }
      it { should eq '2' }
    end
    puts "Control 6.3 log_warnings = #{log_error_verbosity;}"
    describe 'The MySQL log_warnings' do
      subject { log_error_verbosity; }
      it { should eq '3' }
    end
  end

end
