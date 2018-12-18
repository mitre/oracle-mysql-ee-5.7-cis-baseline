control "1.5" do
  title "Disable Interactive Login (Scored)"
  desc  "When created, the MySQL user may have interactive access to the operating system, which means that the MySQL user could login to the host as any other user would"
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "1.5"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Execute the following command to assess this recommendation
  getent passwd mysql | egrep '^.*[\/bin\/false|\/sbin\/nologin]$''
  Lack of output implies a finding"
  tag "fix": "Perform the following steps to remediate this setting:
  • Execute one of the following commands in a terminal
  usermod -s /bin/false 
  usermod -s /sbin/nologin"
  tag "Default Value": ""

  describe.one do
    describe passwd.users('mysql') do
     its('shells') { should cmp '/bin/false' }
    end
    describe passwd.users('mysql') do
     its('shells') { should cmp '/sbin/nologin' }
    end
  end
end
