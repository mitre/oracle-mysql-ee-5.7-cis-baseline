control "4.4" do
  title "Ensure 'local_infile' Is Disabled (Scored)"
  desc  "The local_infile parameter dictates whether files located on the MySQL client's computer can be loaded or selected via LOAD DATA INFILE or SELECT local_file."
  impact 0.5
  tag "severity": "medium"
  tag "cis_id": "4.4"
  tag "cis_level": 1
  tag "nist": ['CM-7', 'Rev_4']
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "audit text": "Execute the following SQL statement and ensure the Value field is set to OFF: 
      SHOW VARIABLES WHERE Variable_name = 'local_infile';"
  tag "fix": "Add the following line to the [mysqld] section of the MySQL configuration file and restart the MySQL service:
      local-infile=0"
  tag "Default Value": "ON"

  query = %(select @@local_infile;)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
           
  local_infile = sql_session.query(query).stdout.strip

  describe 'The MySQL local_infile setting' do
    subject { local_infile }
    it { should cmp 0 }
  end
end
 