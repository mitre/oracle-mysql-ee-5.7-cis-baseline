# frozen_string_literal: true

control '2.3' do
  title 'Do Not Reuse User Accounts (Not Scored)'
  desc  'Database user accounts should not be reused for multiple applications or users.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '2.3'
  tag "cis_level": 1
  tag "nist": %w[AC-6 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS on Linux'
  tag "audit text": "Each user should be linked to one of these
    • system accounts
    • a person
    • an application"
  tag "fix": 'Add/Remove users so that each user is only used for one specific purpose'

  query = 'SELECT User FROM mysql.user;'

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))

  mysql_account_list = sql_session.query(query).stdout.strip.split("\n")
  if !mysql_account_list.empty?
    mysql_account_list.each do |user|
      describe "Mysql database user: #{user}" do
        subject { user }
        it { should be_in input('mysql_users') }
      end
    end
  else
    impact 0.0
    describe 'There are no mysql database users, therefore this control is not applicable' do
      skip 'There are no mysql database users, therefore this control is not applicable'
    end
  end
  only_if { os.linux? }
end
