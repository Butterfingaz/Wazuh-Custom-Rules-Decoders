# Wazuh-Custom-Rules-Decoders
Wazuh SIEM Detection Engineering: Custom XML Decoders & MITRE ATT&CK Alerting

## 1. Project Overview
This project demonstrates advanced SIEM engineering using **Wazuh**. Standard SIEM rulesets do not natively parse proprietary or custom internal application logs. To solve this visibility gap, a custom XML decoder (`local_decoder.xml`) was engineered to extract key fields (`dstuser`, `srcip`, `status`), paired with a high-severity correlation rule (`local_rules.xml`) mapped to the **MITRE ATT&CK Framework**.

## 2. Custom XML Decoder (`local_decoder.xml`)
The decoder matches the custom application header (`PAYMENT_APP_AUDIT:`) and uses regular expressions to dynamically parse attacker attributes:

```xml
<decoder name="custom-payment-app">
  <prematch>^PAYMENT_APP_AUDIT:</prematch>
</decoder>

<decoder name="custom-payment-app-fields">
  <parent>custom-payment-app</parent>
  <regex offset="after_parent">user\(=(\S+)\) srcip=(\d+\.\d+\.\d+\.\d+) status\(=(\S+)</\)regex>
  <order>dstuser, srcip, status</order>
</decoder>
```

## 3. Custom Detection Rule (`local_rules.xml`)
Rule `100105` evaluates the decoded fields and triggers a Level 12 Critical alert upon detecting unauthorized privilege escalation attempts:

```xml
<group name="custom_app,authentication_failures,">
  <rule id="100105" level="12">
    <decoded_as>custom-payment-app</decoded_as>
    <field name="status">^UNAUTHORIZED_ADMIN_ACCESS\$</field>
    <description>CRITICAL: Unauthorized admin API access attempt detected on Payment App by user (dstuser) from IP (srcip).</description>
    <mitre>
      <id>T1078</id>
      <id>T1190</id>
    </mitre>
  </rule>
</group>
```

## 4. Engineering Verification Proof

1. <img width="904" height="174" alt="Project Workspace" src="https://github.com/user-attachments/assets/d6726a69-bfcc-40c6-8899-dd0adf809e97" />

2. <img width="921" height="220" alt="Custom Wazuh Decoder" src="https://github.com/user-attachments/assets/fd96d9cb-44a5-4dda-89c8-df960fe8282e" />

3. <img width="907" height="475" alt="Custom Wazuh Detection Rule" src="https://github.com/user-attachments/assets/dd4d7e63-5b7d-437c-b9ac-1bf758f8cac4" />

4. 

https://github.com/user-attachments/assets/3a245156-e2d3-4500-8fa9-4e83f3869148




* **MITRE ATT&CK Mappings:** `T1078` (Valid Accounts) & `T1190` (Exploit Public-Facing Application).
