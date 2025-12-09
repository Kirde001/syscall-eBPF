#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sqlite3
import signal
import sys
import os
import syslog
import configparser
from datetime import datetime
from bcc import BPF

# Пути
DB_PATH = "/var/lib/syscall-inspector/data.db"
DB_DIR = os.path.dirname(DB_PATH)
CONFIG_PATH = "/etc/syscall-inspector/config.conf"

# Улучшенная eBPF программа с получением PPID
bpf_program = """
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;  // Добавили Parent PID
    u32 uid;
    u32 type;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN]; // Имя родителя
    char fname[256];
};

BPF_PERF_OUTPUT(events);

// Вспомогательная функция для заполнения данных
static void fill_data(struct data_t *data, u32 type) {
    struct task_struct *task;
    struct task_struct *parent;

    task = (struct task_struct *)bpf_get_current_task();
    parent = task->real_parent;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->ppid = parent->pid; // Берем PID родителя из ядра
    data->type = type;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_kernel(&data->pcomm, sizeof(data->pcomm), parent->comm); // Имя родителя
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

    // Первичный фильтр в ядре: только /etc/
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
        self.wazuh_enabled = False
        self.my_pid = os.getpid()  # Запоминаем свой PID
        
        # Черный список процессов (шум)
        self.ignore_comms = {
            "syscall-inspect", "python3", "wazuh-agent", 
            "filebeat", "systemd", "auditd", "sqlite3"
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
                if 'General' in config and 'wazuh_enabled' in config['General']:
                    self.wazuh_enabled = config['General'].getboolean('wazuh_enabled')
        except Exception:
            self.wazuh_enabled = False

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
            config_dir = os.path.dirname(CONFIG_PATH)
            os.makedirs(config_dir, exist_ok=True)
        except Exception:
            sys.exit(1)

    def log_event(self, severity, event_type, process, pid, ppid, pcomm, details):
        timestamp = datetime.now().isoformat()
        
        # Обогащаем детали информацией о родителе (как в Sysmon)
        enriched_details = f"{details} [Parent: {pcomm} ({ppid})]"

        if self.wazuh_enabled:
            priority = syslog.LOG_INFO
            if severity == "high": priority = syslog.LOG_ALERT
            elif severity == "medium": priority = syslog.LOG_WARNING
            
            # Пишем в Syslog
            msg = f"WAZUH_EVENT: {event_type} | PROCESS: {process} | PID: {pid} | PPID: {ppid} | DETAILS: {details}"
            syslog.syslog(priority, msg)

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
        
        # === ГЛАВНЫЙ ФИЛЬТР (Python уровень) ===
        
        # 1. Игнорируем самих себя и свои дочерние процессы
        if event.pid == self.my_pid or event.ppid == self.my_pid:
            return

        # 2. Игнорируем шумные процессы по имени
        comm = event.comm.decode('utf-8', 'replace').strip()
        if comm in self.ignore_comms:
            return
            
        # 3. Дополнительные проверки (можно расширять)
        fname = event.fname.decode('utf-8', 'replace')
        pcomm = event.pcomm.decode('utf-8', 'replace')
        
        # Логика типов
        if event.type == 1: # Execve
            self.log_event("medium", "process_execution", comm, event.pid, event.ppid, pcomm, f"Запуск команды: {fname}")
            
        elif event.type == 2: # Openat
            # Игнорируем доступ к шумным файлам (например, ld.so.cache)
            if "ld.so.cache" in fname or "nsswitch.conf" in fname:
                return
                
            self.log_event("high", "sensitive_file_access", comm, event.pid, event.ppid, pcomm, f"Доступ к файлу: {fname}")

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
