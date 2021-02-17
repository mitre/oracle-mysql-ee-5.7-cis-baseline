# frozen_string_literal: true

control '3.3' do
  title "Ensure 'log_error' Has Appropriate Permissions and Ownership (Scored)"
  desc  "MySQL can operate using a variety of log files, each used for different purposes.
  These are the binary log, error log, slow query log, relay log, audit log and general log.
  Because these are files on the host operating system, they are subject to the permissions and ownership structure provided by the host and may be accessible by users other than the MySQL user"
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '3.3'
  tag "cis_level": 1
  tag "nist": %w[AU-9 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS on Linux'
  tag "audit text": "Perform the following steps to assess this recommendation:
      • Execute the following SQL statement to determine the Value of log_error
      show variables like 'log_error';
      • Execute the following command at a terminal prompt to list all log_error.* files
      ls <log_error>.*
      • For each file listed, execute the following command
      ls -l <log_error> | egrep '^-[r|w]{2}-[r|w]{2}----\s*.*$'
      Lack of output implies a finding."
  tag "fix": "Execute the following command for each log file location requiring corrected permissions and ownership:
      chmod 660 <log file>
      chown mysql:mysql <log file>"


  log_error = mysql_session(input('user'), input('password'), input('host')).query("select @@log_error;").stdout.strip.split.first

  only_if("#{log_error} file exist.") do
    file(log_error).exist?
  end

  describe file(log_error.to_s) do
    its('owner') { should eq 'mysql' }
    its('group') { should eq 'mysql' }
    its('mode') { should be <= 0o660 }
  end
  only_if { os.linux? }
end
