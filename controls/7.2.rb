control "7.2" do
  title "Ensure 'secure_auth' is set to 'ON' (Scored)"
  desc  "This option dictates whether the server will deny connections by clients that attempt to use accounts that have their password stored in the mysql_old_password format."
  impact 0.5
  tag "severity": "medium"
  tag "cis_id": "7.2"
  tag "cis_level": 1
  tag "cis_level": 2
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "Profile Applicability": "Level 2 - MySQL RDBMS"
  tag "audit text": "
  Execute the following SQL statement and ensure the Value field is not set to ON: 
    SHOW VARIABLES WHERE Variable_name = 'secure_auth';"
  tag "fix": "
  Add the following line to [mysqld] portions of the MySQL option file to establish the recommended state:
    secure_auth=ON
  "
  tag "Default Value": "Before MySQL 5.6.5, this option is disabled by default. As of MySQL 5.6.5, it is enabled by default; to disable it, use --skip-secure-auth."

  query = %(SELECT @@secure_auth;)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
           
  secure_auth = sql_session.query(query).stdout.strip

  describe 'The MySQL secure_auth' do
    subject { secure_auth  }
    it {should cmp 1 }
  end
end
