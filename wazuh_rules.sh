  <group name="firewall,portscan">
    <rule id="120001" level="12">
      <if_group>firewall</if_group>
      <match>PORTSCAN-DETECTED</match>
      <description>
        TCP Port Scan detected
      </description>
      <mitre>
        <id>T1046</id>
      </mitre>
    </rule>
  </group>

  <group name="log4j Web attack, log4j docker attack">
    <rule id="110050" level="15">
      <match>jndi:</match>
      <description>
          EARLY BLOCK: Log4Shell detected before proxy pass
      </description>
      <mitre>
          <id>T1190</id>
      </mitre>
    </rule>

    <rule id="110002" level="7">
      <if_group>web|accesslog|attack|json|docker</if_group>
      <regex type="pcre2">(?i)(((\$|24)\S*)((\{|7B)\S*)((\S*j\S*n\S*d\S*i))|JHtqbmRp)</regex>
      <description>Possible Log4j RCE attack attempt detected.</description>
      <mitre>
        <id>T1190</id>
        <id>T1210</id>
        <id>T1211</id>
      </mitre>
    </rule>

   <rule id="110004" level="7">
      <decoded_as>json</decoded_as>
      <field name="log" type="pcre2">(?i)(((\$|24)\S*)((\{|7B)\S*)((\S*j\S*n\S*d\S*i))|JHtqbmRp)</field>
      <description>Possible Log4j RCE attack attempt detected in Docker Container.</description>
      <mitre>
        <id>T1190</id>
        <id>T1210</id>
        <id>T1211</id>
      </mitre>
    </rule>

    <rule id="110003" level="12">
      <if_sid>110002</if_sid>
      <regex type="pcre2">ldap[s]?|rmi|dns|nis|iiop|corba|nds|http|lower|upper|(\$\{\S*\w\}\S*)+</regex>
      <description>Log4j RCE attack attempt detected.</description>
      <mitre>
        <id>T1190</id>
        <id>T1210</id>
        <id>T1211</id>
      </mitre>
    
    </rule>
     <rule id="110005" level="12">
      <if_sid>110004</if_sid>
      <field name="log" type="pcre2">ldap[s]?|rmi|dns|nis|iiop|corba|nds|http|lower|upper|(\$\{\S*\w\}\S*)+</field>
      <description>Log4j RCE attack attempt confirmed in Docker Container via outbound protocol.</description>
      <mitre>
        <id>T1190</id>
        <id>T1210</id>
        <id>T1211</id>
      </mitre>
    </rule>

     <!-- Java Spawn Shell
    <rule id="110030" level="14">
      <if_sid>80700</if_sid>
      <field name="audit.exe" type="pcre2">/bin/bash|/bin/sh</field>
      <description>
        CRITICAL: Java process spawned a shell. Possible Log4Shell RCE success.
      </description>
      <mitre>
        <id>T1059</id>
        <id>T1190</id>
      </mitre>
    </rule>

    <rule id="110031" level="14">
      <if_sid>110030</if_sid>
      <field name="audit.command" type="pcre2">
          (?i)nc|curl|wget|scp|ftp|python|python3|touch|chmod|chown|rm|cat|echo|bash|sh
      </field>
      <description>
        CRITICAL: Post exploitation command after Log4Shell RCE.
      </description>
      <mitre>
        <id>T1059</id>
        <id>T1105</id>
      </mitre>
    </rule>
  </group> 

  </group name="Log4Shell Remote Code Execution">
    <rule id="110040" level="15">
      <decoded_as>json</decoded_as>
      <field name="log">javax.el.ELProcessor</field>
      <description>
          CRITICAL: Log4Shell JNDI exploitation detected (ELProcessor execution)
      </description>
      <mitre>
          <id>T1190</id>
          <id>T1059</id>
      </mitre>
    </rule>
  <group>

  <group name="attacker callback">
    <rule id="110025" level="12">
      <if_sid>110010</if_sid> <field name="audit.execve.a1" type="pcre2">connect|curl|wget|nc</field>
      <regex type="pcre2">(:1389|:1099|:4444)</regex>
      <description>CRITICAL: Defended Policy - Rogue container outbound network call initiated targeting exploitation infrastructure ports.</description>
      <mitre>
        <id>T1071</id> </mitre>
    </rule>
  </group>

  <group name="cred_access,">
    <!--Detect access to offline password storing files-->
      <rule id="100110" level="7">
        <if_sid>80700</if_sid>
        <list field="audit.key" lookup="match_key_value" check_value="passwd">etc/lists/audit-keys</list>
        <description>File access - The file $(audit.file.name) was accessed</description>
        <group>audit_command,</group>
        <mitre>
          <id>T1003.008</id>
        </mitre>
      </rule>

      <rule id="100120" level="10">
        <if_sid>80700</if_sid>
        <list field="audit.key" lookup="match_key_value" check_value="shadow">etc/lists/audit-keys</list>
        <description>Possible adversary activity - $(audit.file.name) was accessed</description>
        <group>audit_command,</group>
        <mitre>
          <id>T1003.008</id>
        </mitre>
      </rule>

    <!--Detecting suspicious activities related to unsecured credentials -->
      <rule id="100131" level="0">
        <if_sid>80700</if_sid>
        <list field="audit.key" lookup="match_key_value" check_value="ssh">etc/lists/audit-keys</list>
        <description>Possible adversary activity - $(audit.file.name) was accessed</description>
        <group>audit_command,</group>
      </rule>

      <rule id="100132" level="0">
        <if_sid>80700</if_sid>
        <list field="audit.key" lookup="match_key_value" check_value="history">etc/lists/audit-keys</list>
        <description>Possible adversary activity - $(audit.file.name) was accessed</description>
        <group>audit_command,</group>
      </rule>

      <rule id="100133" level="0">
        <if_sid>80700</if_sid>
        <field name="audit.exe" type="pcre2">/usr/bin/*grep</field>
        <field name="audit.execve.a2">cred|password|login</field>
        <description>Possible adversary activity - $(audit.file.name) was accessed</description>
        <group>audit_command,</group>
      </rule>

      <rule id="100130" level="10">
        <if_sid>100131, 100132, 100133</if_sid>
        <description>Possible adversary activity - searching for previously used credentials in system files</description>
        <group>audit_command,</group>
        <mitre>
          <id>T1552.001</id>
        </mitre>
      </rule>
  </group>

  <group name="lateral movement inside container">
    <rule id="110010" level="3">
      <if_sid>80700</if_sid>
      <field name="audit.key">docker_lateral</field>
      <description>Wazuh-EDR: Intercepted system command execution sequence inside containerized environment.</description>
    </rule>

    <rule id="110012" level="12" frequency="5" timeframe="60">
      <if_matched_sid>110010</if_matched_sid>
      <field name="audit.exe" type="pcre2">/bin/ssh|/usr/bin/nmap|/bin/nc|/usr/bin/curl|/bin/bash</field>
      <description>CRITICAL: High Frequency Enumeration - Active lateral movement tools deployment detected inside container environment.</description>
      <mitre>
        <id>T1210</id>
        <id>T1021</id>
      </mitre>
    </rule>
  </group>

  <group name="internal movement">
    <!-- Reverse Shell Detection -->
    <rule id="110032" level="15">
      <if_sid>80700</if_sid>
      <regex type="pcre2">
        /dev/tcp|nc\s+-e|bash\s+-i
      </regex>
      <description>
        CRITICAL: Possible reverse shell activity detected.
      </description>
      <mitre>
        <id>T1059</id>
        <id>T1071</id>
      </mitre>
    </rule>

    <!-- Access Secrets -->
    <rule id="110033" level="12">
      <if_sid>80700</if_sid>
      <regex type="pcre2">
        /app/config
      </regex>
      <description>
        Credential discovery activity detected inside container.
      </description>
      <mitre>
        <id>T1552.001</id>
      </mitre>
    </rule>

    <!-- Redis Access -->
    <rule id="110034" level="12">
      <if_sid>80700</if_sid>
      <field name="audit.exe" type="pcre2">
        redis-cli
      </field>
      <description>
        Lateral movement attempt via Redis service.
      </description>
      <mitre>
        <id>T1210</id>
      </mitre>
    </rule>

   <!-- MYSQL Access -->
    <rule id="110035" level="12">
      <if_sid>80700</if_sid>
      <field name="audit.exe" type="pcre2">
        mysql
      </field>
      <description>
        Internal database access detected from compromised container.
      </description>
      <mitre>
        <id>T1210</id>
      </mitre>
    </rule>
  </group>

  <group name="container_escape,">
    <rule id="110020" level="14">
      <if_sid>80700</if_sid>
      <field name="audit.key">container_escape</field>
      <field name="audit.exe" type="pcre2">^(?!/usr/lib/systemd/systemd-executor)</field>
    <description>CRITICAL: Privilege Escalation - Container escape technique identified via host namespace manipulation syscalls.</description>
      <mitre>
        <id>T1611</id> </mitre>
    </rule>  
  </group>

  <group name="Docker Overlay Modification,">
    <rule id="100111" level="5">
      <match type="pcre2">/var/lib/docker/overlay2</match>
      <description>Wazuh FIM: Structural modification sequence spotted inside Docker storage driver path (overlay2).</description>
    </rule>

    <rule id="100121" level="10">
      <if_sid>100111</if_sid>
      <match type="pcre2">"event"\s*:\s*"added"</match>
      <regex type="pcre2">/var/lib/docker/overlay2/.*/diff/</regex>
      <description>CRITICAL: Container Immutability Violation - Unauthorized file payload addition detected inside the container ephemeral disk write layer</description>
      <mitre>
        <id>T1574</id> <!-- Hijack Execution Flow -->
        <id>T1105</id> <!-- Ingress Tool Transfer / Download Malware -->
      </mitre>
    </rule>

    <rule id="100122" level="10">
      <if_sid>100111</if_sid>
      <field name="event" type="pcre2">modified|modify</field>
      <!-- Regex untuk mendeteksi perubahan pada folder krusial di dalam container diff layer -->
      <field name="path" type="pcre2">/overlay2/[a-z0-9]+/diff/(bin|sbin|etc|usr/bin|usr/sbin)/</field>
      <description>CRITICAL: Container Immutability Violation - Core system internal binary path configuration (/bin, /sbin, /etc) modified by an external threat.</description>
      <mitre>
        <id>T1485</id> <!-- Data Destruction / Tampering -->
      </mitre>
    </rule>
  </group>

  <group name="Environment Health">
    <!-- Rule for container resources information. -->
    <rule id="100100" level="4">
      <decoded_as>docker-container-resource</decoded_as>
      <description>Docker: Container $(container_name) Resources</description>
      <group>container_resource,</group>
    </rule>

    <!-- Rule to trigger when container CPU and memory usage are above 80%. -->
    <rule id="100101" level="12">
      <if_sid>100100</if_sid>
      <field name="container_cpu_usage" type="pcre2">^(0*[8-9]\d|0*[1-9]\d{2,})</field>
      <field name="container_memory_perc" type="pcre2">^(0*[8-9]\d|0*[1-9]\d{2,})</field>
      <description>Docker: Container $(container_name) CPU usage ($(container_cpu_usage)) and memory usage ($(container_memory_perc)) is over 80%</description>
      <group>container_resource,</group>
    </rule>

    <!-- Rule to trigger when container CPU usage is above 80%. -->
    <rule id="100102" level="12">
      <if_sid>100100</if_sid>
      <field name="container_cpu_usage" type="pcre2">^(0*[8-9]\d|0*[1-9]\d{2,})</field>
      <description>Docker: Container $(container_name) CPU usage ($(container_cpu_usage)) is over 80%</description>
      <group>container_resource,</group>
    </rule>

    <!-- Rule to trigger when container memory usage is above 80%. -->
    <rule id="100103" level="12">
      <if_sid>100100</if_sid>
      <field name="container_memory_perc" type="pcre2">^(0*[8-9]\d|0*[1-9]\d{2,})</field>
      <description>Docker: Container $(container_name) memory usage ($(container_memory_perc)) is over 80%</description>
      <group>container_resource,</group>
    </rule>

    <!-- Rule for container health information. -->
    <rule id="100105" level="4">
      <decoded_as>docker-container-health</decoded_as>
      <description>Docker: Container $(container_name) is $(container_health_status)</description>
      <group>container_health,</group>
    </rule>

    <!-- Rule to trigger when a container is unhealthy. -->
    <rule id="100106" level="12">
      <if_sid>100105</if_sid>
      <field name="container_health_status">^unhealthy$</field>
      <description>Docker: Container $(container_name) is $(container_health_status)</description>
      <group>container_health,</group>
    </rule>
  </group>


  <group name="cowrie,honeypot,">
    <rule id="100200" level="5">
      <field name="eventid">cowrie.login.failed</field>
      <description>Cowrie SSH failed login attempt</description>
    </rule>

    <rule id="100201" level="10">
      <field name="eventid">cowrie.login.success</field>
      <description>Cowrie SSH successful login</description>
    </rule>

    <rule id="100202" level="8">
      <field name="eventid">cowrie.command.input</field>
      <description>Cowrie command executed</description>
    </rule>

    <rule id="100203" level="12">
      <if_sid>100202</if_sid>
      <match>wget|curl|chmod|bash|sh</match>
      <description>Cowrie possible malware download/execution attempt</description>
    </rule>
  </group>