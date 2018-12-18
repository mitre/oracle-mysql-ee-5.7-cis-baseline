control "1.3" do
  title "Disable MySQL Command History (Scored)"
  desc  "On Linux/UNIX, the MySQL client logs statements executed interactively to a history
  file. By default, this file is named .mysql_history in the user's home directory. Most interactive commands run in the MySQL client application are saved to a history file. 
  The MySQL command history should be disabled."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "1.3"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 2
  tag "audit text": "Execute the following commands to assess this recommendation:
  find /home -name '.mysql_history'
  For each file returned determine whether that file is symbolically linked to /dev/null."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Remove .mysql_history if it exists.
  2. Use either of the techniques below to prevent it from being created again:
  1. Set the MYSQL_HISTFILE environment variable to /dev/null. This will need to be placed in the shell's startup script.
  2. Create $HOME/.mysql_history as a symbolic to /dev/null.
  > ln -s /dev/null $HOME/.mysql_history
  "
  tag "Default Value": "By default, the MySQL command history file is located in $HOME/.mysql_history"

  mysql_history_file = command("find / -name '.mysql_history'").stdout.strip

  describe 'The MySql history file' do
    subject { file("#{mysql_history_file}") }
    its('link_path') { should eq '/dev/null' }
  end
end
#in progress