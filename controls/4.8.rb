# frozen_string_literal: true

control '4.8' do
  title "Ensure 'secure_file_priv' Is Not Empty (Scored)"
  desc  "The secure_file_priv option restricts to paths used by LOAD DATA INFILE or SELECT local_file.
        It is recommended that this option be set to a file system location that contains only resources expected to be loaded by MySQL."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '4.8'
  tag "cis_level": 1
  tag "nist": %w[AC-6 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "Execute the following SQL statement and ensure one row is returned:
      SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv' AND Value<>'';
      Note: The Value should contain a valid path."
  tag "fix": "Add the following line to the [mysqld] section of the MySQL configuration file and restart the MySQL service:
      secure_file_priv=<path_to_load_directory>"
  tag "Default Value": 'No value set.'

  secure_file_priv = mysql_session(input('user'), input('password'), input('host')).query("select @@secure_file_priv;").stdout.strip
  # puts "select @@secure_file_priv; = #{secure_file_priv}"
  describe 'The secure_file_priv variable' do
    subject { secure_file_priv }
    it { should_not be_empty }
  end

end
