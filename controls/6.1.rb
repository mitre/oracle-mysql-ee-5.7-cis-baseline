control "6.1" do
  title "Ensure 'log_error' Is Not Empty (Scored)"
  desc  "The error log contains information about events such as mysqld starting and stopping, when a table needs to be checked or repaired, and, 
  depending on the host operating system, stack traces when mysqld fails."
  impact 0.5
  tag "severity": "medium" 
  tag "cis_id": "6.1"
  tag "cis_level": 1
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "audit text": "
  Execute the following SQL statement to audit this setting:
    SHOW variables LIKE 'log_error';
  Ensure the Value returned is not empty."
  tag "fix": "Perform the following actions to remediate this setting:
  1. Open the MySQL configuration file (my.cnf or my.ini)
  2. Set the log-error option to the path for the error log"

  query = %(select @@log_error;)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
           
  log_error = sql_session.query(query).stdout.strip.split

  describe 'The MySQL log_error' do
    subject { log_error }
    it {should_not be_empty}
  end
end