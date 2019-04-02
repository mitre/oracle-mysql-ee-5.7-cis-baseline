control "6.3" do
  title "Ensure 'log_warnings' Is Set to '2' (Scored)"
  desc  "The log_warnings system variable, enabled by default, provides additional information to the MySQL log. 
  A value of 1 enables logging of warning messages, and higher integer values tend to enable more logging.
  NOTE: log_warnings has been deprecated as of MySQL 5.7.2. 
  Setting log_warnings will also cause log_error_verbosity to be set.The variable scope for log_warnings is global.
  "
  impact 0.5 
  tag "severity": "medium"  
  tag "cis_id": "6.3"
  tag "cis_level": 2
  tag "nist": ['AU-2', 'Rev_4']
  tag "Profile Applicability": "Level 2 - MySQL RDBMS"
  tag "audit text": "Execute the following SQL statement to assess this recommendation:
    SHOW GLOBAL VARIABLES LIKE 'log_warnings';
  Ensure the Value returned equals 2."
  tag "fix": "Perform the following actions to remediate this setting:
  • Open the MySQL configuration file (my.cnf)
  • Ensure the following line is found in the mysqld section 
    log-warnings = 2"
  tag "Default Value": "The option is enabled (1) by default."

  query = %(SELECT @@log_warnings;)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
           
  log_warnings = sql_session.query(query).stdout.strip

  describe 'The MySQL log_warnings' do
    subject { log_warnings }
    it {should cmp 2 }
  end  
end