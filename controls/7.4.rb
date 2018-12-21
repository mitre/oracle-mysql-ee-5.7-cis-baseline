control "7.4" do
  title "Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER' (Scored)"
  desc  "NO_AUTO_CREATE_USER is an option for sql_mode that prevents a GRANT statement from 
  automatically creating a user when authentication information is not provided."
  impact 0.5
  tag "severity": "medium" 
  tag "cis_id": "7.4"
  tag "cis_level": 1
  tag "cis_level": 2
  tag "Profile Applicability": "Level 1 - MySQL RDBMS on Linux"
  tag "Profile Applicability": "Level 2 - MySQL RDBMS on Linux"
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "Profile Applicability": "Level 2 - MySQL RDBMS"
  tag "audit text": "
  Execute the following SQL statements to assess this recommendation: 
      SELECT @@global.sql_mode;
      SELECT @@session.sql_mode;
  Ensure that each result contains NO_AUTO_CREATE_USER.
  "
  tag "fix": "
  Perform the following actions to remediate this setting:
  1. Open the MySQL configuration file (my.cnf)
  2. Find the sql_mode setting in the [mysqld] area
  3. Add the NO_AUTO_CREATE_USER to the sql_mode setting"

  global_query = %(SELECT @@global.sql_mode;)
  session_query = %(SELECT @@session.sql_mode;)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
           
  global_sql_mode = sql_session.query(global_query).stdout.strip
  session_sql_mode = sql_session.query(session_query).stdout.strip

  describe 'The MySQL global sql mode' do
    subject { global_sql_mode }
    it {should include 'NO_AUTO_CREATE_USER' }
  end

  describe 'The MySQL session sql mode' do
    subject { session_sql_mode }
    it {should include 'NO_AUTO_CREATE_USER' }
  end
end
