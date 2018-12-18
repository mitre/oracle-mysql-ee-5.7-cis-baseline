control "4.5" do
  title "Ensure 'mysqld' Is Not Started with '--skip-grant-tables' (Scored)"
  desc  "This option causes mysqld to start without using the privilege system."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "4.5"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Perform the following to determine if the recommended state is in place:
  • Open the MySQL configuration (e.g. my.cnf) file and search for skip-grant-tables
  • Ensure skip-grant-tables is set to FALSE"
  tag "fix": "Perform the following to establish the recommended state:
  • Open the MySQL configuration (e.g. my.cnf) file and set: 
    skip-grant-tables = FALSE"
  tag "Default Value": ""

  describe mysql_conf do
    its('skip-grant-tables') { should cmp 'FALSE' }
  end
end
