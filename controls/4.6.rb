# frozen_string_literal: true

control '4.6' do
  title "Ensure '--skip-symbolic-links' Is Enabled (Scored)"
  desc  "The symbolic-links and skip-symbolic-links options for MySQL determine whether symbolic link support is available.
  When use of symbolic links are enabled, they have different effects depending on the host platform.
  When symbolic links are disabled, then symbolic links stored in files or entries in tables are not used by the database."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '4.6'
  tag "cis_level": 1
  tag "nist": %w[CM-7 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "Execute the following SQL statement to assess this recommendation:
    SHOW variables LIKE 'have_symlink';
  Ensure the Value returned is DISABLED."
  tag "fix": "Perform the following actions to remediate this setting:
  • Open the MySQL configuration file (my.cnf)
  • Locate skip_symbolic_links in the configuration
  • Set the skip_symbolic_links to YES or 1
  NOTE: If skip_symbolic_links does not exist, add it to the configuration file in the mysqld section.
  "

  query = %(select @@have_symlink;)
  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))
  have_symlink = sql_session.query(query).stdout.strip

  describe.one do
    describe 'The MySQL have_symlink setting' do
      subject { have_symlink }
      it { should cmp 'DISABLED' }
    end
    describe mysql_conf.params('mysqld') do
      its('skip_symbolic_links') { should eq '1' }
    end
    describe mysql_conf.params('mysqld') do
      its('skip_symbolic_links') { should eq 'YES' }
    end
  end
end
