control "2.3" do
  title "Do Not Reuse User Accounts (Not Scored)"
  desc  "Database user accounts should not be reused for multiple applications or users."
  impact 0.0 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "2.3"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Each user should be linked to one of these
    • system accounts
    • a person
    • an application"
  tag "fix": "Add/Remove users so that each user is only used for one specific purpose"
  tag "Default Value": ""

  query = 'SELECT User FROM mysql.user;'
    
  ##  puts datadir
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
  #session = mysql_session('root','P@ssw0rd1')
           
 mysql_account_list = sql_session.query(query).stdout.strip.split("\n")
  mysql_account_list.each do |user|
   describe "Mysql database user: #{user}" do
      subject { user }
      it { should be_in attribute('mysql_users') }
    end
  end

end
