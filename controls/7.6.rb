control '7.6' do
  title 'Ensure Password Policy Is in Place (Scored)'
  desc  'Password complexity includes password characteristics such as length, case, length, and character sets.'
  impact 0.5
  tag "severity": 'medium'
  tag "cis_level": 1
  tag "nist": ['IA-5(1)', 'Rev_4']
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS on Linux'
  tag "Profile Applicability": 'Level 1 - MySQL RDBMS'
  tag "audit text": "Execute the following SQL statements to assess this recommendation:
    SHOW VARIABLES LIKE 'validate_password%';

  The result set from the above statement should show:
    • validate_password_length should be 14 or more
    • validate_password_mixed_case_count should be 1 or more
    • validate_password_number_count should be 1 or more
    • validate_password_special_char_count should be 1 or more
    • validate_password_policy should be MEDIUM or STRONG

  The following lines should be present in the global configuration:
    plugin-load=validate_password.so
    validate-password=FORCE_PLUS_PERMANENT

  Check if users have a password which is identical to the username:
    * the Password field is now called authentication_string
    SELECT User,authentication_string,Host FROM mysql.user
    WHERE authentication_string=CONCAT('*', UPPER(SHA1(UNHEX(SHA1(user)))));

  NOTE: This method is only capable of checking the post-4.1 password format which is also known as mysql_native_password."
  tag "fix": "Add to the global configuration:

      plugin-load=validate_password.so
      validate-password=FORCE_PLUS_PERMANENT
       validate_password_length=14
       validate_password_mixed_case_count=1
       validate_password_number_count=1
       validate_password_special_char_count=1
       validate_password_policy=MEDIUM

  And change passwords for users which have passwords which are identical to their username."

  validate_password_length_query = %{SELECT @@validate_password_length}
  validate_password_mixed_case_count_query = %{SELECT @@validate_password_mixed_case_count}
  validate_password_number_count_query = %{SELECT @@validate_password_number_count}
  validate_password_special_char_count_query = %{SELECT @@validate_password_special_char_count}
  validate_password_policy_query = %{SELECT @@validate_password_policy}
  validate_password_check_user_name_query = %{SELECT @@validate_password_check_user_name}
  users_wih_username_equal_to_password_query = %{SELECT User,authentication_string,Host FROM mysql.user
    WHERE authentication_string=CONCAT('*', UPPER(SHA1(UNHEX(SHA1(user)))));}

  sql_session = mysql_session(attribute('user'), attribute('password'), attribute('host'), attribute('port'))

  validate_password_length = sql_session.query(validate_password_length_query).stdout.strip
  validate_password_mixed_case_count = sql_session.query(validate_password_mixed_case_count_query).stdout.strip
  validate_password_number_count = sql_session.query(validate_password_number_count_query).stdout.strip
  validate_password_special_char_count = sql_session.query(validate_password_special_char_count_query).stdout.strip
  validate_password_policy = sql_session.query(validate_password_policy_query).stdout.strip
  validate_password_check_user_name = sql_session.query(validate_password_check_user_name_query).stdout.strip
  users_wih_username_equal_to_password = sql_session.query(users_wih_username_equal_to_password_query).stdout.strip

  describe 'The MySQL validate_password_length variable' do
    subject { validate_password_length }
    it { should cmp >= 14 }
  end

  describe 'The MySQL validate_password_mixed_case_count variable' do
    subject { validate_password_mixed_case_count }
    it { should cmp >= 1 }
  end

  describe 'The MySQL validate_password_number_count variable' do
    subject { validate_password_number_count }
    it { should cmp >= 1 }
  end

  describe 'The MySQL validate_password_special_char_count variable' do
    subject { validate_password_special_char_count }
    it { should cmp >= 1 }
  end

  describe.one do
    describe 'The MySQL validate_password_policy variable' do
      subject { validate_password_policy }
      it { should cmp 'MEDIUM' }
    end
    describe 'The MySQL validate_password_policy variable' do
      subject { validate_password_policy }
      it { should cmp 'STRONG' }
    end
  end

  describe mysql_conf do
    its('plugin-load') { should cmp 'validate_password.so' }
    its('validate-password') { should cmp 'FORCE_PLUS_PERMANENT' }
  end

  describe.one do
    describe 'The MySQL validate_password_check_user_name variable' do
      subject { validate_password_check_user_name }
      it { should cmp 1 }
    end
    describe 'The MySQL users with their password identical to their username' do
      subject { users_wih_username_equal_to_password }
      it { should be_empty }
    end
  end
end
