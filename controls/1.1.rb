control "1.1" do
  title "1.1 Place Databases on Non-System Partitions (Scored)"
  desc  "It is generally accepted that host operating systems should include different filesystem partitions for different purposes. 
  One set of filesystems are typically called system partitions, and are generally reserved for host system/application operation. 
  The other set of filesystems are typically called non-system partitions, and such locations are generally reserved for storing data."
  impact 0.5 
  tag "severity": "medium"
  tag "cis_id": "1.1"
  tag "cis_level": 1
  tag "nist": ['SC-2', 'Rev_4']
  tag "Profile Applicability": "Level 1 - MySQL RDBMS on Linux"
  tag "audit text": "Execute the following steps to assess this recommendation:
  • Discover the datadir by executing the following SQL statement
  show variables where variable_name = 'datadir';
  • Using the returned datadir Value from the above query, execute the following in a system terminal
  df -h <datadir Value>
  The output returned from the df command above should not include root ('/'), '/var', or '/usr'."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Choose a non-system partition new location for the MySQL data
  2. Stop mysqld using a command like: service mysql stop
  3. Copy the data using a command like: cp -rp <datadir Value> <new location> 4. Set the datadir location to the new location in the MySQL configuration file
  5. Start mysqld using a command like: service mysql start
  NOTE: On some Linux distributions you may need to additionally modify apparmor settings. For example, on a Ubuntu 14.04.1 system edit the file /etc/apparmor.d/usr.sbin.mysqld so that the datadir access is appropriate. The original might look like this:
  # Allow data dir access 
  /var/lib/mysql/ r, 
  /var/lib/mysql/** rwk,
  Alter those two paths to be the new location you chose above. For example, if that new location were /media/mysql, then the /etc/apparmor.d/usr.sbin.mysqld file should include something like this:
  # Allow data dir access /media/mysql/ r,
   /media/mysql/** rwk,
"
  tag "Default Value": "Not Applicable"

  query = %(select @@datadir;)

  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
           
  datadir = sql_session.query(query).stdout.strip.split

  describe 'The mysql data directory partition installed on' do
   subject { command("df -h #{datadir}").stdout }
    it {should_not include '/'}
  end

  describe 'The mysql data directory partition installed on' do
   subject { command("df -h #{datadir}").stdout }
    it {should_not include '/var'}
  end

  describe 'The mysql data directory partition installed on' do
   subject { command("df -h #{datadir}").stdout }
    it {should_not include '/usr'}
  end
  only_if { os.linux? }
end
