# frozen_string_literal: true

control '3.1' do
  title "Ensure 'datadir' Has Appropriate Permissions and Ownership (Scored)"
  desc  'The data directory is the location of the MySQL databases.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '3.1'
  tag "cis_level": 1
  tag "nist": %w[AC-3 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS on Linux'
  tag "audit text": "Perform the following steps to assess this recommendation:
      • Execute the following SQL statement to determine the Value of datadir
        show variables where variable_name = 'datadir';
      • Execute the following command at a terminal prompt
        ls -l <datadir>/.. | egrep '^d[r|w|x]{3}------\s*.\s*mysql\s*mysql\s*\d*.*mysql'
        Lack of output implies a finding.
        "
  tag "fix": "Execute the following commands at a terminal prompt:
      chmod 700 <datadir>
      chown mysql:mysql <datadir>"


  datadir = mysql_session(
                          input('user'), input('password'), input('host')
                          ).query("select @@datadir;").stdout.strip.split.first
  puts "Datadir = #{datadir}"

  only_if("#{datadir} file exist.") do
    directory(datadir).exist?
  end

  describe directory(datadir.to_s) do
    it { should exist }
    its('owner') { should eq 'mysql' }
    its('group') { should eq 'mysql' }
    its('mode') { should cmp '0700' }
  end
  only_if { os.linux? }
end
