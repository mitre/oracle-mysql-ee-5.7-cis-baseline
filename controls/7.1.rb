control '7.1' do
  title "Ensure 'old_passwords' Is Not Set to '1' (Scored)"
  desc  "This variable controls the password hashing method used by the PASSWORD() function and for the IDENTIFIED BY clause of the CREATE USER and GRANT statements.
  The value can be one of the following:
    • 0 - authenticate with the mysql_native_password plugin
    • 1 - authenticate with the mysql_old_password plugin
    • 2 - authenticate with the sha256_password plugin"
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '7.1'
  tag "cis_level": 1
  tag "nist": ['IA-5(1)', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS on Linux'
  tag "audit text": "
  Execute the following SQL statement to assess this recommendation:
    SHOW VARIABLES WHERE Variable_name = 'old_passwords';
  Ensure the Value field is not set to 1."
  tag "fix": "Configure mysql to leverage the mysql_native_password or sha256_password plugin. For more information, see:
  • http://dev.mysql.com/doc/refman/5.6/en/password-hashing.html
  • http://dev.mysql.com/doc/refman/5.6/en/sha256-authentication-plugin.html"
  tag "Default Value": '0'

  query = %{SELECT @@old_passwords;}
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  old_passwords = sql_session.query(query).stdout.strip

  describe 'The MySQL old_passwords' do
    subject { old_passwords }
    it { should_not cmp 1 }
  end
  only_if { os.linux? }
end
