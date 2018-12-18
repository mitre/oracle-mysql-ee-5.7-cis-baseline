control "9.1" do
  title "Ensure Replication Traffic Is Secured (Not Scored)"
  desc  "The replication traffic between servers should be secured. 
  Security measures should include ensuring the confidentiality and integrity of the traffic, 
  and performing mutual authentication between the servers before performing replication.
  "
  impact 0.5 #double check
  tag "severity": "medium"  #double check
  tag "cis_id": "9.1"
  tag "cis_control": ["No CIS Control", "6.1"] #don't know
  tag "cis_level": 1
  tag "audit text": "Check if the replication traffic is using one or more of the following to provide confidentiality and integrity for the traffic, and mutual authentication for the servers:
    • A private network
    • A VPN
    • SSL/TLS
    • A SSH Tunnel"
  tag "fix": "Secure the network traffic using one or more technologies to provide confidentiality and integrity for the traffic, and mutual authentication for the servers."
  tag "Default Value": ""

  
end
