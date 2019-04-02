control "2.4" do
  title "Do Not Use Default or Shared Cryptographic Material (Not Scored)"
  desc  "The cryptographic material used by MySQL, such as digital certificates and encryption keys, should be used only for MySQL and only for one instance. 
  Default cryptographic material should not be used because others are likely to have copies of them"
  impact 0.5
  tag "severity": "medium"
  tag "cis_id": "2.4"
  tag "cis_level": 
  tag "nist": ['IA-5(2)', 'Rev_4']
  tag "Profile Applicability": "Level 2 - MySQL RDBMS on Linux"
  tag "audit text": "Review all cryptographic material and check to see if any of it is default or is used for other MySQL instances or for purposes other than MySQL"
  tag "fix": "Generate new certificates, keys, and other cryptographic material as needed for each affected MySQL instance"
  describe 'A manual review is required to ensure the default or shared cryptographic material is not being used' do
    skip 'A manual review is required to ensure the default or shared cryptographic material is not being used'
  end
  only_if { os.linux? }
end
