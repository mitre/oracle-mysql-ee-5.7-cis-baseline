control "5.9" do
  title "Ensure DML/DDL Grants Are Limited to Specific Databases and Users (Scored)"
  desc  "DML/DDL includes the set of privileges used to modify or create data structures. 
  This includes INSERT, SELECT, UPDATE, DELETE, DROP, CREATE, and ALTER privileges."
  impact 0.5
  tag "severity": "medium"
  tag "cis_id": "5.9"
  tag "cis_level": 1
  tag "nist": ['AC-6', 'Rev_4']
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "audit text": "
  Execute the following SQL statement to audit this setting:
    SELECT User,Host,Db 
    FROM mysql.db
    WHERE Select_priv='Y'
      OR Insert_priv='Y' 
      OR Update_priv='Y' 
      OR Delete_priv='Y' 
      OR Create_priv='Y' 
      OR Drop_priv='Y'
      OR Alter_priv='Y';
  Ensure all users returned should have these privileges on the indicated databases. 
  NOTE: Global grants are covered in Recommendation 4.1."
  tag "fix": "
  Perform the following steps to remediate this setting:
  1. Enumerate the unauthorized users, hosts, and databases returned in the result set of the audit procedure
  2. For each user, issue the following SQL statement (replace '<user>'' with the unauthorized user,
  '<host>'' with host name, and '<database>' with the database name):
    REVOKE SELECT ON <host>.<database> FROM <user>; 
    REVOKE INSERT ON <host>.<database> FROM <user>; 
    REVOKE UPDATE ON <host>.<database> FROM <user>; 
    REVOKE DELETE ON <host>.<database> FROM <user>;
     REVOKE CREATE ON <host>.<database> FROM <user>; 
     REVOKE DROP ON <host>.<database> FROM <user>; 
     REVOKE ALTER ON <host>.<database> FROM <user>;"
  query = %(SELECT User
    FROM mysql.db
    WHERE Select_priv='Y'
      OR Insert_priv='Y' 
      OR Update_priv='Y' 
      OR Delete_priv='Y' 
      OR Create_priv='Y' 
      OR Drop_priv='Y'
      OR Alter_priv='Y';)
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
  mysql_user_privs = sql_session.query(query).stdout.strip.split("\n") 

  if !mysql_user_privs.empty?
    mysql_user_privs.each do |user|
      describe "The mysql user: #{user} with privileges to modify or create data structures" do
        subject { user }
        it { should be_in attribute('mysql_users_allowed_modify_or_create') }
      end
    end
  end
  if mysql_user_privs.empty?
    impact 0.0
    desc 'There are no mysql users allowed to modify or create data structures, therefore this control is not applicable'
    describe 'There are no mysql users allowed to modify or create data structures, therefore this control is not applicable' do
      skip 'There are no mysql users allowed to modify or create data structures, therefore this control is not applicable'
    end
  end
end