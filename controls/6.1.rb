# frozen_string_literal: true

control '6.1' do
  title "Ensure 'log_error' Is Not Empty (Scored)"
  desc  "The error log contains information about events such as mysqld starting and stopping, when a table needs to be checked or repaired, and,
        depending on the host operating system, stack traces when mysqld fails."
  impact 0.5
  tag "severity": 'medium'
  tag "cis_id": '6.1'
  tag "cis_level": 1
  tag "nist": %w[AU-2 Rev_4]
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "
      Execute the following SQL statement to audit this setting:
      SHOW variables LIKE 'log_error';
      Ensure the Value returned is not empty."
  tag "fix": "Perform the following actions to remediate this setting:
      1. Open the MySQL configuration file (my.cnf or my.ini)
      2. Set the log-error option to the path for the error log"


  log_error_verbosity = mysql_session(input('user'), input('password'), input('host')).query("select @@log_error_verbosity;").stdout.strip
  #puts "Control 6.1 \t select @@log_error_verbosity; = #{log_error_verbosity} "
  describe 'The MySQL log_error' do
    subject { log_error_verbosity }
    it { should_not be_empty }
  end
end

# inspec exec /tmp/shubhangigaherwar/git-repos/oracle-mysql-ee-5.7-cis-baseline/controls/4.9.rb --color --show-progress -i ~/.ssh/id_rsa --bastion-host=devrls1786srv1.coupadev.com --bastion-user=rundeck -t=ssh://rundeck@dev946dbm.int.coupadev.com --input host=dev946dbm.int.coupadev.com user=rapid7_scan password=rapid7_scan mysql_users=[root,mysql.session,mysql.sys,mysql.infoschema,repl,klosetd,shasta,sqladmin,sqlreadonly,vahana,collectd,telegraf,rapid7_scan,data_insight,pmm] mysql_administrative_users=[root,mysql.session,mysql.infoschema,sqladmin,sqlreadonly,repl,telegraf,data_insight,vahana,rapid7_scan,shasta,klosetd,pmm] mysql_users_allowed_modify_or_create=[root,mysql.session,shasta,klosetd,pmm] is_mysql_server_slave_configured=false
