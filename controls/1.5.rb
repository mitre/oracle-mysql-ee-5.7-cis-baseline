control '1.5' do
  title 'Disable Interactive Login (Scored)'
  desc  'When created, the MySQL user may have interactive access to the operating system, which means that the MySQL user could login to the host as any other user would'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '1.5'
  tag "cis_level": 2
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": 'Level 2 - MySQL RDBMS on Linux'
  tag "check": "Execute the following command to assess this recommendation
  getent passwd mysql | egrep '^.*[\/bin\/false|\/sbin\/nologin]$''
  Lack of output implies a finding"
  tag "fix": "Perform the following steps to remediate this setting:
  • Execute one of the following commands in a terminal
  usermod -s /bin/false
  usermod -s /sbin/nologin"

  describe.one do
    describe passwd.users('mysql') do
      its('shells') { should cmp '/bin/false' }
    end
    describe passwd.users('mysql') do
      its('shells') { should cmp '/sbin/nologin' }
    end
  end
  only_if { os.linux? }
end
