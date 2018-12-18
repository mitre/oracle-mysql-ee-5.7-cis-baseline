control "1.4" do
  title "Verify that 'MYSQL_PWD' Is Not Set (Scored)"
  desc  "MySQL can read a default database password from an environment variable called MYSQL_PWD. Avoiding use of this environment variable can better safeguard the confidentiality of MySQL credentials."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "1.4"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "To assess this recommendation, use the /proc filesystem to determine if MYSQL_PWD is currently set for any process
  grep MYSQL_PWD /proc/*/environ
  This may return one entry for the process which is executing the grep command."
  tag "fix": "Check which users and/or scripts are setting MYSQL_PWD and change them to use a more secure method."
  tag "Default Value": "Not set"

  describe 'The MYSQL_PWD environment variable' do 
    subject { command('grep MYSQL_PWD /proc/*/environ').stdout.strip }
    it {should eq ''}
  end

end
