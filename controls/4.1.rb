control '4.1' do
  title '4.1 Ensure Latest Security Patches Are Applied (Not Scored)'
  desc  "Periodically, updates to MySQL server are released to resolve bugs, mitigate vulnerabilities, and provide new features.
  It is recommended that MySQL installations are up to date with the latest security updates"
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '4.1'
  tag "cis_level": 1
  tag "nist": ['SI-2', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS on Linux'
  tag "check": "
  Execute the following SQL statement to identify the MySQL server version:
    SHOW VARIABLES WHERE Variable_name LIKE 'version';
  Now compare the version with the security announcements from Oracle and/or the OS if the OS packages are used"
  tag "fix": 'Install the latest patches for your version or upgrade to the latest version'
  query = %{select @@version;}
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  mysql_version = sql_session.query(query).stdout.strip

  describe "The mysql version installed: #{mysql_version}" do
    subject { mysql_version }
    it { should include /input('approved_mysql_version')*/ }
  end
end
