#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sqlite3
import signal
import sys
import os
from bcc import BPF

DB_PATH = "/var/lib/syscall-inspector/data.db"
DB_DIR = os.path.dirname(DB_PATH)
FILTER_PATH = "/var/lib/syscall-inspector/filter.conf"

bpf_program_template = """
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    unsigned long syscall_nr;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct data_t data = {};
    char comm[TASK_COMM_LEN]; 
    bpf_get_current_comm(&comm, sizeof(comm));

    {filter_check}

    data.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(data.comm, comm, TASK_COMM_LEN); 
    data.syscall_nr = args->id;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

class SyscallDaemon:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self.bpf = None
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop()
        sys.exit(0)

    def init_db(self):
        try:
            os.makedirs(DB_DIR, exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, timeout=5)
            cursor = self.conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS syscalls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    pid INTEGER,
                    comm TEXT,
                    syscall_nr BIGINT
                )
            ''')
            self.conn.commit()
        except Exception as e:
            print(f"Ошибка инициализации БД: {e}", file=sys.stderr)
            sys.exit(1)

    def process_event(self, cpu, data, size):
        try:
            event = self.bpf["events"].event(data)
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO syscalls (pid, comm, syscall_nr) VALUES (?, ?, ?)",
                (event.pid, event.comm.decode('utf-8', 'replace'), event.syscall_nr)
            )
            self.conn.commit()
        except Exception as e:
            if self.conn and "closed" not in str(e):
                print(f"Ошибка записи в БД: {e}", file=sys.stderr)

    def get_filter_code(self):
        target_comm = "" # По умолчанию отслеживаем все
        if os.path.exists(FILTER_PATH):
            try:
                with open(FILTER_PATH, 'r') as f:
                    target_comm = f.read().strip()
            except Exception as e:
                print(f"Не удалось прочитать файл фильтра {FILTER_PATH}: {e}", file=sys.stderr)

        if not target_comm or target_comm == "*":
            print("Фильтр не установлен. Отслеживаем все процессы.", file=sys.stderr)
            return "" # Возвращаем пустую строку, фильтрации не будет

        if len(target_comm) > 15:
             target_comm = target_comm[:15]
        
        print(f"Применение фильтра eBPF для comm: '{target_comm}'", file=sys.stderr)
        filter_c = f'if (__builtin_memcmp(comm, "{target_comm}", {len(target_comm)}) != 0) {{ return 0; }}'
        return filter_c

    def run(self):
        self.init_db()
        filter_check_c = self.get_filter_code()
        final_bpf_program = bpf_program_template.format(filter_check=filter_check_c)
        print(f"Загрузка eBPF с фильтром: {filter_check_c}", file=sys.stderr)
        try:
            self.bpf = BPF(text=final_bpf_program)
        except Exception as e:
            print(f"Критическая ошибка загрузки eBPF: {e}", file=sys.stderr)
            print("--- Текст программы BPF: ---", file=sys.stderr)
            print(final_bpf_program, file=sys.stderr)
            print("---------------------------", file=sys.stderr)
            sys.exit(1)
            
        self.bpf["events"].open_perf_buffer(self.process_event)
        while True:
            try:
                self.bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Ошибка в цикле poll: {e}", file=sys.stderr)

    def stop(self):
        if self.conn:
            self.conn.close()

def main():
    daemon = SyscallDaemon(DB_PATH)
    try:
        daemon.run()
    except Exception as e:
        print(f"Необработанная ошибка: {e}", file=sys.stderr)
    finally:
        daemon.stop()

if __name__ == "__main__":
    main()
