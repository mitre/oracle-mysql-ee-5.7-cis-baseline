control "9.1" do
  title "Ensure Replication Traffic Is Secured (Not Scored)"
  desc  "The replication traffic between servers should be secured. 
  Security measures should include ensuring the confidentiality and integrity of the traffic, 
  and performing mutual authentication between the servers before performing replication.
  "
  impact 0.5
  tag "severity": "medium"
  tag "cis_id": "9.1"
  tag "cis_level": 1
  tag "Profile Applicability": "Level 1 - MySQL RDBMS"
  tag "audit text": "Check if the replication traffic is using one or more of the following to provide confidentiality and integrity for the traffic, and mutual authentication for the servers:
    • A private network
    • A VPN
    • SSL/TLS
    • A SSH Tunnel"
  tag "fix": "Secure the network traffic using one or more technologies to provide confidentiality and integrity for the traffic, and mutual authentication for the servers."

  describe 'A manual review is required to ensure the replication traffic is secured' do
    skip 'A manual review is required to ensure the replication traffic is secured'
  end
end
