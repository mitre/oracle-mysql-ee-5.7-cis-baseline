control "9.3" do
  title "Ensure 'master_info_repository' Is Set to 'TABLE' (Scored)"
  desc  "The master_info_repository setting determines to where a slave logs master status and connection information. 
  The options are FILE or TABLE. Note also that this setting is associated with the sync_master_info setting as well."
  impact 0.5
  tag "severity": "medium"
  tag "cis_id": "9.3"
  tag "cis_level": 2
  tag "nist": ['AU-2', 'Rev_4']
  tag "Profile Applicability": "Level 2 - MySQL RDBMS"
  tag "audit text": "Execute the following SQL statement to assess this recommendation:
    SHOW GLOBAL VARIABLES LIKE 'master_info_repository';
  The result should be TABLE instead of FILE.
  NOTE: There also should not be a master.info file in the datadir."
  tag "fix": "Perform the following actions to remediate this setting:
  1. Open the MySQL configuration file (my.cnf)
  2. Locate master_info_repository
  3. Set the master_info_repository value to TABLE
  NOTE: If master_info_repository does not exist, add it to the configuration file."
  tag "Default Value": "FILE"
  query = 'select @@master_info_repository'
  sql_session = mysql_session(attribute('user'),attribute('password'),attribute('host'),attribute('port'))
  master_info_repository = sql_session.query(query).stdout.strip       
  describe "The master_info_repository" do
    subject { master_info_repository }
    it { should cmp 'TABLE' }
  end
end
