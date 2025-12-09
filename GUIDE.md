# Настройка интеграции модуля  и Wazuh

### 1. Конфигурация модуля
Файл: `/etc/syscall-inspector/config.conf`

```ini
[General]
siem_enabled = true
log_format = json
```

# Пример для Wazuh (проверено именно с этой SIEM):
### в конфиге агента - /var/ossec/etc/ossec.conf должен быть блок (для читки логов)
```bash
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/messages</location> 
</localfile>
```

# Пример правил для проверки:
```bash
<group name="syscall_inspector,">
  <rule id="100010" level="1">
    <decoded_as>json</decoded_as>
    <field name="event_type">\.+</field>
    <description>Syscall event base</description>
  </rule>

  <rule id="100011" level="10">
    <if_sid>100010</if_sid>
    <field name="event_type">sensitive_file_access</field>
    <description>eBPF alert - sensitive file access detected by $(process)</description>
    <group>pci_dss_10.2.4,gdpr_IV_35.7.d,</group>
  </rule>

  <rule id="100012" level="3">
    <if_sid>100010</if_sid>
    <field name="event_type">process_execution</field>
    <description>eBPF info - process execution detected: $(process)</description>
  </rule>
</group>
```
# После изменений - systemctl restart wazuh-manager

# Проверка основной службы - systemctl status syscall-inspector

# Проверка генерации логов - cat /etc/shadow. После проверка системного журнала: journalctl -t syscall-ebpf -n 10

# Поиск ошибок на агенте: grep -i "error" /var/ossec/logs/ossec.log

# Проверяем, идут ли логи до Wazuh-сервера: grep "syscall-ebpf" /var/ossec/logs/archives/archives.json | tail

