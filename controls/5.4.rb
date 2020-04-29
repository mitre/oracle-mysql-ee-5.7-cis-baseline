# frozen_string_literal: true

control '5.4' do
  title "Ensure 'super_priv' Is Not Set to 'Y' for Non-Administrative Users (Scored)"
  desc  "The SUPER privilege found in the mysql.user table governs the use of a variety of MySQL features.
  These features include, CHANGE MASTER TO, KILL, mysql admin kill option, PURGE BINARY LOGS, SET GLOBAL, mysqladmin debug option, logging control, and more."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '5.4'
  tag "cis_level": 1
  tag "nist": %w[AC-6 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "Execute the following SQL statement to audit this setting:
    select user, host from mysql.user where Super_priv = 'Y';
  Ensure only administrative users are returned in the result set."
  tag "fix": "Perform the following steps to remediate this setting:
  1. Enumerate the non-administrative users found in the result set of the audit procedure
  2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user:
    REVOKE SUPER ON *.* FROM '<user>';"
  query = %(select user from mysql.user where Super_priv = 'Y';)

  sql_session = mysql_session(input('user'), input('password'), input('host'), input('port'))
  mysql_user_super_priv = sql_session.query(query).stdout.strip.split("\n")

  unless mysql_user_super_priv.empty?
    mysql_user_super_priv.each do |user|
      describe "The mysql user: #{user} with super_priv" do
        subject { user }
        it { should be_in input('mysql_administrative_users') }
      end
    end
  end
  if mysql_user_super_priv.empty?
    impact 0.0
    describe 'There are no mysql users with super_priv allowed, therefore this control is not applicable' do
      skip 'There are no mysql users with super_priv allowed, therefore this control is not applicable'
    end
  end
end
