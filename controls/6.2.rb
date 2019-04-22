control '6.2' do
  title 'Ensure Log Files Are Stored on a Non-System Partition (Scored)'
  desc  "MySQL log files can be set in the MySQL configuration to exist anywhere on the filesystem.
  It is common practice to ensure that the system filesystem is left uncluttered by applicationlogs.
  System filesystems include the root, /var, or /usr."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.2'
  tag "cis_level": 1
  tag "nist": ['AU-9(2)', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS in Linux'
  tag "audit text": "Execute the following SQL statement to assess this recommendation:
    SELECT @@global.log_bin_basename;
  Ensure the value returned does not indicate root ('/'), /var, or /usr."
  tag "fix": "Perform the following actions to remediate this setting:
  1. Open the MySQL configuration file (my.cnf)
  2. Locate the log-bin entry and set it to a file not on root ('/'), /var, or /usr"

  query = %{select @@global.log_bin_basename;}

  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  global_log_bin_basename = sql_session.query(query).stdout.strip.split

  describe 'The mysql log files partition installed on' do
    subject { command("df -h #{global_log_bin_basename}").stdout }
    it { should_not include '/' }
  end

  describe 'The mysql log files partition installed on' do
    subject { command("df -h #{global_log_bin_basename}").stdout }
    it { should_not include '/var' }
  end

  describe 'The mysql log files partition installed on' do
    subject { command("df -h #{global_log_bin_basename}").stdout }
    it { should_not include '/usr' }
  end
  only_if { os.linux? }
end
