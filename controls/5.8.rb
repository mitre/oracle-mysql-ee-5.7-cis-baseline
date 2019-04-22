control "5.8" do
  title "Ensure 'repl_slave_priv' Is Not Set to 'Y' for Non-Slave Users (Scored)"
  desc  "The REPLICATION SLAVE privilege governs whether a given user 
  (in the context of the master server) can request updates that have been made on the master server."
  impact 0.5
  tag "severity": "medium" 
  tag "cis_id": "5.8"
  tag "cis_level": 1
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "audit text": "Execute the following SQL statement to audit this setting:
      SELECT user, host FROM mysql.user WHERE Repl_slave_priv = 'Y';
  Ensure only accounts designated for slave users are granted this privilege."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Enumerate the non-slave users found in the result set of the audit procedure
  2. For each user, issue the following SQL statement (replace '<user>'' with the non-slave user):
    REVOKE REPLICATION SLAVE ON *.* FROM <user>;
  Use the REVOKE statement to remove the SUPER privilege from users who shouldn't have it."

  query = %(select user from mysql.user where Repl_slave_priv = 'Y';)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
  mysql_user_repl_slave_priv = sql_session.query(query).stdout.strip.split("\n") 

  if !mysql_user_repl_slave_priv.empty?
    mysql_user_repl_slave_priv.each do |user|
      describe "The mysql user: #{user} with repl_slave_priv" do
        subject { user }
        it { should be_in attribute('mysql_administrative_users') }
      end
    end
  end
  if mysql_user_repl_slave_priv.empty?
    impact 0.0
    describe 'There are no mysql users with repl_slave_priv allowed, therefore this control is not applicable' do
      skip 'There are no mysql users with repl_slave_priv allowed, therefore this control is not applicable'
    end
  end
end