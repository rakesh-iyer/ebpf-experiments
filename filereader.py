#!/usr/bin/python3

# this framework allows high level orchestration of berkeley packet filter handlers
from bcc import BPF

# define the ebpf program.
open_program = """
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>


BPF_PERF_OUTPUT(events);  // Declare a BPF map to transmit data to user space
BPF_HASH(audit_log_fd, u32, u32);
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    char comm[100];
    char fname[100];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_probe_read_user_str(&fname, sizeof(fname), (void *)filename);
    if ((fname[0] == 't' && fname[1] == 'e'  && fname[2] == 's' && fname[3] == 't' && fname[4] == 0) &&
        (comm[0] == 'c' && comm[1] == 'a' && comm[2] == 't' && comm[3] == 0)) {
        u32 tid = bpf_get_current_pid_tgid();
        audit_log_fd.update(&tid, &tid);
        bpf_trace_printk("%s opened file %s.\\n", comm, fname);
    }
    return 0;
};

// lets record the relevant file descriptor for a particular file opened by a particular app.
int kretprobe__sys_openat(struct pt_regs *ctx) {
  int fd = PT_REGS_RC(ctx);
  u32 tid = bpf_get_current_pid_tgid();
  u32* entry = audit_log_fd.lookup(&tid);
  if (entry != NULL) {
    bpf_trace_printk("File descriptor for %d is %d.\\n", tid, fd);
    audit_log_fd.update(&tid, &fd);
  }
  return 0;
}

int syscall__write(struct pt_regs *ctx, unsigned int fd, const char __user *buf, size_t count)
{
    u32 tid = bpf_get_current_pid_tgid();
    u32* stored_fd = audit_log_fd.lookup(&tid);
    if (stored_fd != NULL && *stored_fd == fd) {
      char read[255];
      bpf_trace_printk("%d writing to file %d.\\n", tid, fd);
      bpf_probe_read_user_str(&read, sizeof(read), (void *)buf);
      bpf_trace_printk("Writing %s.\\n", read);
    }
    return 0;
}
"""

# define the ebpf program.
write_program = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);  // Declare a BPF map to transmit data to user space

int syscall__write(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    char comm[100];
    char fname[100];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_probe_read_user_str(&fname, sizeof(fname), (void *)filename);
    bpf_trace_printk("%s opened file %s.\\n", comm, fname);
    return 0;
};
"""

def instrument_open():
  open_b = BPF(text=open_program)
  # instrumenting the sys_open call.
  syscall = open_b.get_syscall_fnname("openat")
  open_b.attach_kprobe(syscall, fn_name="syscall__openat")
  # need to do this for the program to continue.
  open_b.trace_print()


def instrument_write():
  write_b = BPF(text=write_program)
  # instrumenting the sys_open call.
  syscall = write_b.get_syscall_fnname("openat")
  write_b.attach_kprobe(syscall, fn_name="syscall__write")
  # need to do this for the program to continue.
  write_b.trace_print()

instrument_open()
