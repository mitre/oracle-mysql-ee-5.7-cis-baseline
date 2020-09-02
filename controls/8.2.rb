control '8.2' do
  title "Ensure 'ssl_type' Is Set to 'ANY', 'X509', or 'SPECIFIED' for All Remote Users (Scored)"
  desc  "All network traffic must use SSL/TLS when traveling over untrusted networks.
  SSL/TLS should be enforced on a per-user basis for users which enter the system through the network."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '8.2'
  tag "cis_level": 1
  tag "nist": ['SC-8 (2)', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "check": "
  Execute the following SQL statements to assess this recommendation:
    SELECT user, host, ssl_type FROM mysql.user
    WHERE HOST NOT IN ('::1', '127.0.0.1', 'localhost');
  Ensure the ssl_type for each user returned is equal to ANY, X509, or SPECIFIED.
  NOTE: have_openssl is an alias for have_ssl as of MySQL 5.0.38. MySQL can be build with OpenSSL or YaSSL."
  tag "fix": "Use the GRANT statement to require the use of SSL:
  GRANT USAGE ON *.* TO 'my_user'@'app1.example.com' REQUIRE SSL;
  Note that REQUIRE SSL only enforces SSL. There are options like REQUIRE X509, REQUIRE ISSUER, REQUIRE SUBJECT
  which can be used to further restrict connection options."
  tag "Default Value": 'Not enforced (ssl_type is empty)'

  query = %{SELECT user FROM mysql.user WHERE HOST NOT IN ('::1', '127.0.0.1', 'localhost');}
  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  remote_users = sql_session.query(query).stdout.strip.split("\n")

  remote_users.each do |user|

    query_ssl_type = "SELECT ssl_type FROM mysql.user
    WHERE HOST NOT IN ('::1', '127.0.0.1', 'localhost') AND user = '#{user}';"
    ssl_type = sql_session.query(query_ssl_type).stdout.strip

    describe.one do
      describe "The ssl_type for remote user: #{user}" do
        subject { ssl_type }
        it { should cmp 'ANY' }
      end
      describe "The ssl_type for remote user: #{user}" do
        subject { ssl_type }
        it { should cmp 'X509' }
      end
      describe "The ssl_type for remote user: #{user}" do
        subject { ssl_type }
        it { should cmp 'SPECIFIED' }
      end
    end
  end
  if remote_users.empty?
    impact 0.0
    describe 'There are no mysql remote users, therefore this control is not applicable' do
      skip 'There are no mysql remote users, therefore this control is not applicable'
    end
  end
end
