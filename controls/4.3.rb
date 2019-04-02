control "4.3" do
  title "Ensure 'allow-suspicious-udfs' Is Set to 'FALSE' (Scored)"
  desc  "This option prevents attaching arbitrary shared library functions as user-defined functions by checking for at least one corresponding method named _init, _deinit, _reset, _clear, or _add."
  impact 0.5
  tag "severity": "medium"
  tag "cis_id": "4.3"
  tag "cis_level": 2
  tag "nist": ['CM-7', 'Rev_4']
  tag "Profile Applicability": "Level 2 - MySQL RDBMS"
  tag "audit text": "Perform the following to determine if the recommended state is in place:
  • Ensure --allow-suspicious-udfs is not specified in the the mysqld start up command line.
  • Ensure allow-suspicious-udfs is set to FALSE in the MySQL configuration."
  tag "fix": "Perform the following to establish the recommended state:
  • Remove --allow-suspicious-udfs from the mysqld start up command line.
  • Remove allow-suspicious-udfs from the MySQL option file."
  tag "Default Value": "FALSE"

  describe mysql_conf do
    its('allow-suspicious-udfs') { should be_nil }
  end
  
  describe command('ps aux | grep mysql') do
    its('stdout') { should_not match 'allow-suspicious-udfs' }
  end
end
