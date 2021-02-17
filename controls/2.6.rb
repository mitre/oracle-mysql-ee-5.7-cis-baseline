control '2.6' do
  title "Set a Password Expiry Policy for Specific Users (Not Scored)"
  desc  "Password expiry for specific users provides user passwords with a unique time bounded lifetime."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '2.6'
  tag "cis_level": 1
  tag "nist": ['SC-8 (2)', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "Audit: Returns all users currently using the global setting default_password_life, and hence have no specific user password expiry set.
       SELECT user, host, password_lifetime from mysql.user from mysql.user where password_lifetime IS NULL;"
  tag "Fix: Using the user and host information from the audit procedure, set each user a password lifetime e.g.
       ALTER USER 'jeffrey'@'localhost' PASSWORD EXPIRE INTERVAL 90 DAY;"
  tag "Default Value: NULL. The user's password_lifetime takes on the value set in global default_password_lifetime variable.'"


  sql_session = mysql_session(input('user'), input('password'), input('host'))
  remote_users = sql_session.query(" SELECT user, host, password_lifetime from mysql.user where password_lifetime IS NULL;"
                ).stdout.strip
  puts "remote users= #{remote_users}"
  describe 'Password expiry for specific users provides user passwords with a unique time bounded lifetime.' do
    subject { remote_users }
    it { should be_empty}
  end
  only_if { os.linux? }

end
