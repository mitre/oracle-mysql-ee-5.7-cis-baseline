# frozen_string_literal: true

control '2.4' do
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

  sql_session = mysql_session(input('user'), input('password'), input('host'))

  mysql_account_list = sql_session.query(query).stdout.strip.split("\n")
  puts "SQL session users= #{mysql_account_list}"
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
#
# [rundeck@devrun2045srv1 ~]$ inspec exec /tmp/shubhangigaherwar/git-repos/oracle-mysql-ee-5.7-cis-baseline/controls/2.4.rb  --color --show-progress -i ~/.ssh/id_rsa --bastion-host=devrls1786srv1.coupadev.com --bastion-user=rundeck -t=ssh://rundeck@dev946dbm.int.coupadev.com --input host=dev946dbm.int.coupadev.com user=rapid7_scan password=rapid7_scan mysql_users=[root,mysql.session,mysql.sys,mysql.infoschema,repl,klosetd,shasta,sqladmin,sqlreadonly,vahana,collectd,telegraf,rapid7_scan,data_insight,pmm] mysql_administrative_users=[root,mysql.session,mysql.infoschema,sqladmin,sqlreadonly,repl,telegraf,data_insight,vahana,rapid7_scan,shasta,klosetd,pmm] mysql_users_allowed_modify_or_create=[root,mysql.session,shasta,klosetd,pmm] is_mysql_server_slave_configured=false
# SQL session users= ["6b99da92e424c4bd", "863267522dac1c85", "c11e4f95b8268635", "rapid7_scan", "repl", "data_insight", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "klosetd", "shasta", "telegraf", "sqladmin", "data_insight", "collectd", "data_insight", "mysql.infoschema", "mysql.session", "mysql.sys", "pmm", "root", "sqladmin", "sqlreadonly"]
# FFF.......................
#
# Profile: tests from /tmp/shubhangigaherwar/git-repos/oracle-mysql-ee-5.7-cis-baseline/controls/2.4.rb (tests from .tmp.shubhangigaherwar.git-repos.oracle-mysql-ee-5.7-cis-baseline.controls.2.4.rb)
# Version: (not specified)
# Target:  ssh://rundeck@dev946dbm.int.coupadev.com:22
#
#   ×  2.3: Do Not Reuse User Accounts (Not Scored) (3 failed)
#      ×  Mysql database user: 6b99da92e424c4bd is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      expected `6b99da92e424c4bd` to be in the list: `["root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", "pmm"]`
#      ×  Mysql database user: 863267522dac1c85 is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      expected `863267522dac1c85` to be in the list: `["root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", "pmm"]`
#      ×  Mysql database user: c11e4f95b8268635 is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      expected `c11e4f95b8268635` to be in the list: `["root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", "pmm"]`
#      ✔  Mysql database user: rapid7_scan is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: repl is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: data_insight is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: klosetd is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: shasta is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: sqladmin is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: sqlreadonly is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: vahana is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: collectd is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: klosetd is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: shasta is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: telegraf is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: sqladmin is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: data_insight is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: collectd is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: data_insight is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: mysql.infoschema is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: mysql.session is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: mysql.sys is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: pmm is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: root is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: sqladmin is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#      ✔  Mysql database user: sqlreadonly is expected to be in "root", "mysql.session", "mysql.sys", "mysql.infoschema", "repl", "klosetd", "shasta", "sqladmin", "sqlreadonly", "vahana", "collectd", "telegraf", "rapid7_scan", "data_insight", and "pmm"
#
#
# Profile Summary: 0 successful controls, 1 control failure, 0 controls skipped
# Test Summary: 23 successful, 3 failures, 0 skipped
# [rundeck@devrun2045srv1 ~]$
