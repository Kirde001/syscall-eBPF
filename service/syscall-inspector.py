#!/usr/bin/python3

import sqlite3
import signal
import sys
import os
import syslog
import configparser
import time
import json
from datetime import datetime
from bcc import BPF

DB_PATH = "/var/lib/syscall-inspector/data.db"
DB_DIR = os.path.dirname(DB_PATH)
CONFIG_PATH = "/etc/syscall-inspector/config.conf"

bpf_program = """
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 type;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char fname[256];
};

BPF_PERF_OUTPUT(events);

static void fill_data(struct data_t *data, u32 type) {
    struct task_struct *task;
    struct task_struct *parent;

    task = (struct task_struct *)bpf_get_current_task();
    parent = task->real_parent;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->ppid = parent->pid;
    data->type = type;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_kernel(&data->pcomm, sizeof(data->pcomm), parent->comm);
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    fill_data(&data, 1);
    bpf_probe_read_user(data.fname, sizeof(data.fname), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    fill_data(&data, 2);
    bpf_probe_read_user(data.fname, sizeof(data.fname), args->filename);

    if (data.fname[0] == '/' && data.fname[1] == 'e' && 
        data.fname[2] == 't' && data.fname[3] == 'c') {
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

class SyscallDaemon:
    def __init__(self):
        self.running = True
        self.conn = None
        self.bpf = None
        self.wazuh_enabled = True
        self.log_format = "rfc3164"
        self.my_pid = os.getpid()
        self.dedup_cache = {}
        
        self.ignore_comms = {
            "syscall-inspect", "python3", "wazuh-agent", 
            "filebeat", "systemd", "auditd", "sqlite3",
            "dbus-daemon", "systemd-journal", "systemd-logind"
        }

        syslog.openlog(ident="syscall-ebpf", logoption=syslog.LOG_PID, facility=syslog.LOG_USER)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.running = False

    def load_config(self):
        try:
            config = configparser.ConfigParser()
            if os.path.exists(CONFIG_PATH):
                config.read(CONFIG_PATH)
                if 'General' in config:
                    self.wazuh_enabled = config['General'].getboolean('wazuh_enabled', fallback=True)
                    self.log_format = config['General'].get('log_format', 'rfc3164')
        except Exception:
            self.wazuh_enabled = True
            self.log_format = "rfc3164"

    def init_storage(self):
        try:
            os.makedirs(DB_DIR, exist_ok=True)
            self.conn = sqlite3.connect(DB_PATH, timeout=5)
            os.chmod(DB_PATH, 0o644)
            cursor = self.conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT,
                    event_type TEXT,
                    process TEXT,
                    pid INTEGER,
                    details TEXT
                )
            ''')
            self.conn.commit()
        except Exception:
            sys.exit(1)

    def should_log(self, pid, event_type, details):
        current_time = time.time()
        if len(self.dedup_cache) > 1000:
            self.dedup_cache.clear()

        key = (pid, event_type, details)
        last_time = self.dedup_cache.get(key)

        if last_time and (current_time - last_time < 2.0):
            return False
        
        self.dedup_cache[key] = current_time
        return True

    def send_syslog(self, severity, event_type, process, pid, ppid, details):
        priority = syslog.LOG_INFO
        if severity == "high": priority = syslog.LOG_ALERT
        elif severity == "medium": priority = syslog.LOG_WARNING

        msg = ""
        
        if self.log_format == "json":
            log_dict = {
                "event_type": event_type,
                "process": process,
                "pid": pid,
                "ppid": ppid,
                "details": details,
                "severity": severity,
                "timestamp": datetime.now().isoformat()
            }
            msg = json.dumps(log_dict)

        elif self.log_format == "cef":
            sev_num = 3
            if severity == "high": sev_num = 8
            elif severity == "medium": sev_num = 5
            msg = f"CEF:0|AltLinux|SyscallInspector|1.0|{event_type}|{event_type}|{sev_num}|src=127.0.0.1 proc={process} pid={pid} msg={details}"

        else: 
            msg = f"WAZUH_EVENT: {event_type} | PROCESS: {process} | PID: {pid} | PPID: {ppid} | DETAILS: {details}"

        syslog.syslog(priority, msg)

    def log_event(self, severity, event_type, process, pid, ppid, pcomm, details):
        if not self.should_log(pid, event_type, details):
            return

        timestamp = datetime.now().isoformat()
        enriched_details = f"{details} [Parent: {pcomm} ({ppid})]"

        if self.wazuh_enabled:
            self.send_syslog(severity, event_type, process, pid, ppid, details)

        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO alerts (timestamp, severity, event_type, process, pid, details) VALUES (?, ?, ?, ?, ?, ?)",
                (timestamp, severity, event_type, process, pid, enriched_details)
            )
            self.conn.commit()
        except Exception:
            pass

    def process_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        
        if event.pid == self.my_pid or event.ppid == self.my_pid:
            return

        comm = event.comm.decode('utf-8', 'replace').strip()
        if comm in self.ignore_comms:
            return
            
        fname = event.fname.decode('utf-8', 'replace')
        pcomm = event.pcomm.decode('utf-8', 'replace')
        
        if event.type == 1:
            self.log_event("medium", "process_execution", comm, event.pid, event.ppid, pcomm, f"запуск команды: {fname}")
            
        elif event.type == 2:
            if any(x in fname for x in ["ld.so.cache", "nsswitch.conf", "resolv.conf", "localtime", "os-release"]):
                return
            self.log_event("high", "sensitive_file_access", comm, event.pid, event.ppid, pcomm, f"доступ к файлу: {fname}")


    def run(self):
        self.init_storage()
        self.load_config()
        
        try:
            self.bpf = BPF(text=bpf_program)
        except Exception:
            sys.exit(1)

        self.bpf["events"].open_perf_buffer(self.process_event)
        
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
            except Exception:
                pass
        
        if self.conn:
            self.conn.close()

if __name__ == "__main__":
    SyscallDaemon().run()
