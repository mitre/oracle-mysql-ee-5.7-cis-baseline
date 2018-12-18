control "3.1" do
  title "Ensure 'datadir' Has Appropriate Permissions and Ownership (Scored)"
  desc  "The data directory is the location of the MySQL databases."
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "3.1"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
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
  tag "Default Value": ""



  query = %(select @@datadir;)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
           
  datadir = sql_session.query(query).stdout.strip.split

  describe directory("#{datadir}") do
    it { should exist }
    its('owner') { should eq 'mysql' }
    its('group') { should eq 'mysql' }
    its('mode') { should be <= 0700 }
  end

end