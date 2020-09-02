control '6.4' do
  title "Ensure 'log-raw' Is Set to 'OFF' (Scored)"
  desc  "The log-raw MySQL option determines whether passwords are rewritten by the server so as not to appear in log files as plain text.
  If log-raw is enabled, then passwords are written to the various log files (general query log, slow query log, and binary log) in plain text."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.4'
  tag "cis_level": 1
  tag "nist": ['AU-2', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "check": "
  Perform the following actions to assess this recommendation:
  • Open the MySQL configuration file (my.cnf)
  • Ensure the log-raw entry is present
  • Ensure the log-raw entry is set to OFF"
  tag "fix": "
  Perform the following actions to remediate this setting:
  • Open the MySQL configuration file (my.cnf)
  • Find the log-raw entry and set it as follows
    log-raw = OFF"
  tag "Default Value": 'OFF'

  describe mysql_conf do
    its('log-raw') { should cmp 'OFF' }
  end
end
