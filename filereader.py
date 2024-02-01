#!/usr/bin/python3

# this framework allows high level orchestration of berkeley packet filter handlers
from bcc import BPF

# define the ebpf program.
open_program = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>

#include <bcc/proto.h>

BPF_PERF_OUTPUT(events);  // Declare a BPF map to transmit data to user space
BPF_HASH(audit_log_fd, u32, u32);

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    char comm[50];
    char fname[50];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_probe_read_user_str(&fname, sizeof(fname), (void *)filename);
    if (fname[0] == '/' && fname[1] == 'h' && fname[2] == 'o' && fname[3] == 'm' && fname[4] == 'e' && fname[5] == '/' &&
      fname[6] == 'r' && fname[7] == 'i' && fname[8] == 'y' && fname[9] == 'e' && fname[10] == 'r' && fname[11] == '.' &&
      fname[12] == 'l' && fname[13] == 'i' && fname[14] == 'n' && fname[15] == 'u' && fname[16] == 'x' && fname[17] == '/' &&
      fname[18] == 't' && fname[19] == 'e' && fname[20] == 's' && fname[21] == 't'
      ){ // && comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h') {
        u32 tid = bpf_get_current_pid_tgid();
//        audit_log_fd.update(&comm, &tid);
        audit_log_fd.update(&tid, &dfd);
        bpf_trace_printk("%s, %d opened file %s.\\n", comm, tid, fname);
    }
    return 0;
};

// lets record the relevant file descriptor for a particular file opened by a particular app.
int kretprobe__sys_openat(struct pt_regs *ctx) {
  int fd = PT_REGS_RC(ctx);
  u32 tid = bpf_get_current_pid_tgid();
  char comm[50];
  bpf_get_current_comm(&comm, sizeof(comm));
//  u32* entry = audit_log_fd.lookup(&comm);
  u32* entry = audit_log_fd.lookup(&tid);
  if (entry != NULL) {
    bpf_trace_printk("File descriptor for %d is %d.\\n", tid, fd);
    audit_log_fd.update(&tid, &fd);
  }
  return 0;
}

int syscall__write(struct pt_regs *ctx, unsigned int fd, const char __user *buf, size_t count)
{
    char comm[50];
    bpf_get_current_comm(&comm, sizeof(comm));
    u32 tid = bpf_get_current_pid_tgid();
    u32* stored_fd = audit_log_fd.lookup(&comm);
    if (stored_fd != NULL) {
      bpf_trace_printk("%s writing to file %d:%d.\\n", comm, *stored_fd, fd);
    }
    if (stored_fd != NULL) {
      char read[255];
      bpf_trace_printk("%d writing to file %d.\\n", tid, fd);
      bpf_probe_read_user_str(&read, sizeof(read), (void *)buf);
      bpf_trace_printk("Writing %s.\\n", read);
    }
    return 0;
}
"""

def instrument_open_and_write():
  program = BPF(text=open_program)
  # instrumenting the sys_open call.
  syscall_open = program.get_syscall_fnname("openat")
  program.attach_kprobe(syscall_open, fn_name="syscall__openat")
  syscall_write = program.get_syscall_fnname("write")
  program.attach_kprobe(syscall_write, fn_name="syscall__write")
#  syscall_read = program.get_syscall_fnname("read")
#  program.attach_kprobe(syscall_read, fn_name="syscall__write")
  # need to do this for the program to continue.
  program.trace_print()

instrument_open_and_write()
