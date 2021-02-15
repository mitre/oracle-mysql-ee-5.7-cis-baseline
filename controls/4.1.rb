# frozen_string_literal: true

control '4.1' do
  title '4.1 Ensure Latest Security Patches Are Applied (Not Scored)'
  desc  "Periodically, updates to MySQL server are released to resolve bugs, mitigate vulnerabilities, and provide new features.
  It is recommended that MySQL installations are up to date with the latest security updates"
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '4.1'
  tag "cis_level": 1
  tag "nist": %w[SI-2 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS on Linux'
  tag "audit text": "
      Execute the following SQL statement to identify the MySQL server version:
      SHOW VARIABLES WHERE Variable_name LIKE 'version';
      Now compare the version with the security announcements from Oracle and/or the OS if the OS packages are used"
  tag "fix": 'Install the latest patches for your version or upgrade to the latest version'
  mysql_version = mysql_session(
    attribute('user'), attribute('password'), attribute('host')
  ).query("select @@version;").stdout.strip

  describe 'The mysql version installed' do
    subject { mysql_version }
    it { should cmp >= '8.0.20-11' }
  end
  only_if { os.linux? }
end
