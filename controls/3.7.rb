control '3.7' do
  title 'Ensure SSL Key Files Have Appropriate Permissions and Ownership (Scored)'
  desc  "When configured to use SSL/TLS, MySQL relies on key files, which are stored on the host's filesystem.
  These key files are subject to the host's permissions and ownership structure."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '3.7'
  tag "cis_level": 1
  tag "nist": ['AC-3', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS on Linux'
  tag "check": "To assess this recommendation, locate the SSL key in use by executing the following SQL statement to get the Value of ssl_key:
  show variables where variable_name = 'ssl_key';
  Then, execute the following command to assess the permissions of the Value:
  ls -l <ssl_key Value> | egrep '^-r--------[ \t]*.[ \t]*mysql[ \t]*mysql.*$'
  Lack of output from the above command implies a finding."
  tag "fix": "Execute the following commands at a terminal prompt to remediate these settings using the Value from the audit procedure:
    chown mysql:mysql <ssl_key Value>
    chmod 400 <ssl_key Value>"

  query = %{select @@ssl_key;}

  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  ssl_key = sql_session.query(query).stdout.strip.split

  describe directory(ssl_key.to_s) do
    it { should exist }
    its('owner') { should eq 'mysql' }
    its('group') { should eq 'mysql' }
    its('mode') { should be <= 0400 }
  end
  only_if { os.linux? }
end
