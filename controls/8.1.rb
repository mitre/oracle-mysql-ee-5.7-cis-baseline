# frozen_string_literal: true

control '8.1' do
  title "Ensure 'have_ssl' Is Set to 'YES' (Scored)"
  desc  'All network traffic must use SSL/TLS when traveling over untrusted networks.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '8.1'
  tag "cis_level": 1
  tag "nist": ['SC-8 (2)', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "Execute the following SQL statements to assess this recommendation:
  SHOW variables WHERE variable_name = 'have_ssl';
  Ensure the Value returned is YES.
  NOTE: have_openssl is an alias for have_ssl as of MySQL 5.0.38. MySQL can be build
  with OpenSSL or YaSSL."
  tag "fix": 'Follow the procedures as documented in the MySQL 5.6 Reference Manual to setup SSL.'
  tag "Default Value": 'DISABLED'

  query = %(SELECT @@have_ssl;)
  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  have_ssl = sql_session.query(query).stdout.strip

  describe 'The MySQL have_ssl variable' do
    subject { have_ssl }
    it { should cmp 'YES' }
  end
end
