control "1.2" do
  title "Use Dedicated Least Privileged Account for MySQL Daemon/Service (Scored)"
  desc  "As with any service installed on a host, it can be provided with its own user context. Providing a dedicated user to the service provides the ability to precisely constrain the service within the larger host context."
  impact 0.5
  tag "severity": "medium"
  tag "cis_id": "1.2"
  tag "cis_level": 1
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": "Level 1 - MySQL RDBMS on Linux"
  tag "audit text": "Execute the following command at a terminal prompt to assess this recommendation:
  ps -ef | egrep '^mysql.*$''
  If no lines are returned, then this is a finding.
  NOTE: It is assumed that the MySQL user is mysql. Additionally, you may consider running
  sudo -l as the MySQL user or to check the sudoers file."
  tag "fix": "Create a user which is only used for running MySQL and directly related processes. This user must not have administrative rights to the system."
  describe 'The user runnning the MySQL Daemon/Service' do
    subject { command("ps -ef | egrep '^mysql.*$' | awk {'print $1'}").stdout.strip }
    it { should cmp 'mysql'}
  end
  only_if { os.linux? }
end
