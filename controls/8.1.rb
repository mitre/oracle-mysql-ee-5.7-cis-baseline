control "8.1" do
  title "Ensure 'have_ssl' Is Set to 'YES' (Scored)"
  desc  "All network traffic must use SSL/TLS when traveling over untrusted networks."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "8.1"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Execute the following SQL statements to assess this recommendation:
  SHOW variables WHERE variable_name = 'have_ssl';
  Ensure the Value returned is YES.
  NOTE: have_openssl is an alias for have_ssl as of MySQL 5.0.38. MySQL can be build
  with OpenSSL or YaSSL."
  tag "fix": "Follow the procedures as documented in the MySQL 5.6 Reference Manual to setup SSL."
  tag "Default Value": "DISABLED"

  
end
