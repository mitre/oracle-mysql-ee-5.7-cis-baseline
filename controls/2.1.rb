control '2.1' do
  title 'Dedicate Machine Running MySQL (Not Scored)'
  desc  'It is recommended that MySQL Server software be installed on a dedicated server. This architectural consideration affords flexibility in that the database server can be placed on a separate zone allowing access only from particular hosts and over particular protocols'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '2.1'
  tag "cis_level": 1
  tag "nist": ['SC-2', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS on Linux'
  tag "audit text": 'Verify there are no other roles enabled for the underlying operating system and that no additional applications or services unrelated to the proper operation of the MySQL server software are installed.'
  tag "fix": 'Remove excess applications or services and/or remove unnecessary roles from the underlying operating system'
  describe 'A manual review is required to verfify a dedicated machine is running MySQL' do
    skip 'A manual review is required to verfify a dedicated machine is running MySQL'
  end
  only_if { os.linux? }
end
