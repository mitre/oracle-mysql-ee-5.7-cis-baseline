control "6.10" do
  title "Ensure audit_log_statement_policy is set to ALL (Scored)"
  desc  "This setting controls whether statements are written to the audit log"
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "6.10"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 2
  tag "audit text": "SHOW GLOBAL VARIABLES LIKE 'audit_log_statement_policy';
  It must return ALL"
  tag "fix": "Add this to the mysqld section of the mysql configuration file and restart the server:
  audit_log_statement_policy='ALL'"
  tag "Default Value": "ALL"

  
  query = %(select @@log_error;)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
           
  log_error = sql_session.query(query).stdout.strip.split

  describe 'The MySQL log_error' do
    subject { log_error }
    it {should_not be_empty}
  end
end