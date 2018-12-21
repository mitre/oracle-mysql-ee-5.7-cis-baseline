control "5.2" do
  title "Ensure 'file_priv' Is Not Set to 'Y' for Non-Administrative Users (Scored)"
  desc  "The File_priv privilege found in the mysql.user table is used to allow or disallow a user from reading and writing files on the server host.
  Any user with the File_priv right granted has the ability to:
  • Read files from the local file system that are readable by the MySQL server (this includes world-readable files)
  • Write files to the local file system where the MySQL server has write access"
  impact 0.5 
  tag "severity": "medium" 
  tag "cis_id": "5.2"
  tag "cis_level": 1
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "audit text": "Execute the following SQL statement to audit this setting
    select user, host from mysql.user where File_priv = 'Y';
  Ensure only administrative users are returned in the result set."
  tag "fix": "
  Perform the following steps to remediate this setting:
  1. Enumerate the non-administrative users found in the result set of the audit procedure
  2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user:
    REVOKE FILE ON *.* FROM '<user>';
  "
  query = %(select user from mysql.user where File_priv = 'Y';)
 
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
  mysql_user_file_priv = sql_session.query(query).stdout.strip.split("\n") 


  if !mysql_user_file_priv.empty?
    mysql_user_file_priv.each do |user|
      describe "The mysql user: #{user} with file_priv" do
        subject { user }
        it { should be_in attribute('mysql_administrative_users') }
      end
    end
  end
  
  if mysql_user_file_priv.empty?
    impact 0.0
    desc 'There are no mysql users with file_priv allowed, therefore this control is not applicable'
    describe 'There are no mysql users with file_priv allowed, therefore this control is not applicable' do
      skip 'There are no mysql users with file_priv allowed, therefore this control is not applicable'
    end
  end
end