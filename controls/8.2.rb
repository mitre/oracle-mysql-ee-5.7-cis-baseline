control "8.2" do
  title "Ensure 'ssl_type' Is Set to 'ANY', 'X509', or 'SPECIFIED' for All Remote Users (Scored)"
  desc  "All network traffic must use SSL/TLS when traveling over untrusted networks.
  SSL/TLS should be enforced on a per-user basis for users which enter the system through the network."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "8.2"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "
  Execute the following SQL statements to assess this recommendation:
    SELECT user, host, ssl type FROM mysql.user
    WHERE NOT HOST IN ('::1', '127.0.0.1', 'localhost');
  Ensure the ssl_type for each user returned is equal to ANY, X509, or SPECIFIED.
  NOTE: have_openssl is an alias for have_ssl as of MySQL 5.0.38. MySQL can be build with OpenSSL or YaSSL."
  tag "fix": "Use the GRANT statement to require the use of SSL:
  GRANT USAGE ON *.* TO 'my_user'@'app1.example.com' REQUIRE SSL;
  Note that REQUIRE SSL only enforces SSL. There are options like REQUIRE X509, REQUIRE ISSUER, REQUIRE SUBJECT
  which can be used to further restrict connection options."
  tag "Default Value": "Not enforced (ssl_type is empty)"

  
end
