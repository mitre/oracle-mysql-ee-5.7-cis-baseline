control "2.2" do
  title " Do Not Specify Passwords in Command Line (Not Scored)"
  desc  "When a command is executed on the command line, for example mysql -u admin - ppassword, the password may be visible in the user's shell/command history or in the process list"
  impact 0.0 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "2.2"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Check the process or task list if the password is visible.
  Check the shell or command history if the password is visible"
  tag "fix": "Use -p without password and then enter the password when prompted, use a properly secured .my.cnf file, or store authentication information in encrypted format in .mylogin.cnf"
  tag "Default Value": ""

  get_mysql_login_history = command("history").stdout
  puts get_mysql_login_history
  get_mysql_login_history.each do |login|

    describe 'The mysql login format' do
      subject {"#{login}"}
      it {should eq ''}
      it { should match /mysql\s+-u\s+\w+\s+-p$/}
    end
  end
  describe command('history') do
    its('stdout') {should_not eq ''}
  end
  #mysql\s+-u\s+\w+\s+-p$
end
describe command("history") do
  its("stdout") { should match /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/ }
end

bash_history_file = command("find / -name '.bash_history'").stdout.strip

describe 'The MySql history file' do
    subject { file("#{bash_history_file}") }
   # its('content') { should match /mysql\s+-u\s+\w+\s+-p$/}
    #its('content') { should match  /mysql\s+-u\s+\w+\s+-p\s+\w+$/ }
     its('content') { should_not match  /^mysql\s+-u\s+\w+\s+-p\s*\S*/ }
  end
#might be manual - inspec cannot run history command'


describe 'The MySql history file' do
    subject { file("/root/test.txt") }
   # its('content') { should match /mysql\s+-u\s+\w+\s+-p$/}
    #its('content') { should match  /mysql\s+-u\s+\w+\s+-p\s+\w+$/ }
     its('content') { should match /^mysql\s+-u\s+\w+ -p\s*\w/ }
  end