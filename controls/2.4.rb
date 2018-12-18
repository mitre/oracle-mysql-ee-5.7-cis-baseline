control "2.4" do
  title "Do Not Use Default or Shared Cryptographic Material (Not Scored)"
  desc  "The cryptographic material used by MySQL, such as digital certificates and encryption keys, should be used only for MySQL and only for one instance. 
  Default cryptographic material should not be used because others are likely to have copies of them"
  impact 0.0 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "2.4"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 2
  tag "audit text": "Review all cryptographic material and check to see if any of it is default or is used for other MySQL instances or for purposes other than MySQL"
  tag "fix": "Generate new certificates, keys, and other cryptographic material as needed for each affected MySQL instance"
  tag "Default Value": ""

  
end
