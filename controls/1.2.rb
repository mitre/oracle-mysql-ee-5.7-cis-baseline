control "1.2" do
  title "Use Dedicated Least Privileged Account for MySQL Daemon/Service (Scored)"
  desc  "As with any service installed on a host, it can be provided with its own user context. Providing a dedicated user to the service provides the ability to precisely constrain the service within the larger host context."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "1.2"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Execute the following command at a terminal prompt to assess this recommendation:
  ps -ef | egrep '^mysql.*$''
  If no lines are returned, then this is a finding.
  NOTE: It is assumed that the MySQL user is mysql. Additionally, you may consider running
  sudo -l as the MySQL user or to check the sudoers file."
  tag "fix": "Create a user which is only used for running MySQL and directly related processes. This user must not have administrative rights to the system."
  tag "Default Value": ""

  describe 'The user runnning the MySQL Daemon/Service' do
    subject { command("ps -ef | egrep '^mysql.*$' | awk {'print $1'}").stdout.strip }
    it { should cmp 'mysql'}
  end
end
