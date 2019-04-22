control "9.2" do
  title "Ensure 'MASTER_SSL_VERIFY_SERVER_CERT' Is Set to 'YES' or '1' (Scored)"
  desc  "In the MySQL slave context the setting MASTER_SSL_VERIFY_SERVER_CERT indicates whether the slave should verify the master's certificate. 
  This configuration item may be set to Yes or No, and unless SSL has been enabled on the slave, the value will be ignored."
  impact 0.5
  tag "severity": "medium"
  tag "cis_id": "9.2"
  tag "cis_level": 1
  tag "nist": ['SC-23', 'Rev_4']
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "audit text": "To assess this recommendation, issue the following statement:
  select ssl_verify_server_cert from mysql.slave_master_info;
  Verify the value of ssl_verify_server_cert is 1."
  tag "fix": "To remediate this setting you must use the CHANGE MASTER TO command.
              STOP SLAVE; -- required if replication was already running 
              CHANGE MASTER TO MASTER_SSL_VERIFY_SERVER_CERT=1;
              START SLAVE; -- required if you want to restart replication"

  query = 'select ssl_verify_server_cert from mysql.slave_master_info;'
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
  master_ssl_verify_server_cert = sql_session.query(query).stdout.strip
  if attribute('is_mysql_server_slave_configured')         
   describe "The MASTER_SSL_VERIFY_SERVER_CERT" do
      subject { master_ssl_verify_server_cert }
      it { should cmp 1 }
    end
  else
    impact 0.0
    describe 'There is no mysql server slave configured, therfore this control is not applicable' do
      skip 'There is no mysql server slave configured, therfore this control is not applicable'
    end
  end
end
 