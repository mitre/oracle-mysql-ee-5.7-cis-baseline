# frozen_string_literal: true

control '4.7' do
  title "Ensure the 'daemon_memcached' Plugin Is Disabled (Scored)"
  desc  'The InnoDB memcached Plugin allows users to access data stored in InnoDB with the memcached protocol.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '4.7'
  tag "cis_level": 1
  tag "nist": %w[CM-7 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "Execute the following SQL statement to assess this recommendation:
      SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME='daemon_memcached'
      Ensure that no rows are returned."
  tag "fix": "To remediate this setting, issue the following command in the MySQL command-line client:
      uninstall plugin daemon_memcached;
      This uninstalls the memcached plugin from the MySQL server.
      "
  tag "Default Value": 'disabled'

    daemon_memcached_plugin = mysql_session(input('user'), input('password'), input('host')).query("SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME='daemon_memcached'").stdout.strip
    # puts "SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME='daemon_memcached' = #{daemon_memcached_plugin}"
    describe 'The daemon_memcached plugins installed' do
      subject { daemon_memcached_plugin }
      it { should be_empty }
    end
end
