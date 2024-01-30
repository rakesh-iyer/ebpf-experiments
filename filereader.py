#!/usr/bin/python3

# this framework allows high level orchestration of berkeley packet filter handlers
from bcc import BPF

# define the ebpf program.
program = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);  // Declare a BPF map to transmit data to user space

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    char comm[100];
    char fname[100];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_probe_read_user_str(&fname, sizeof(fname), (void *)filename);
    bpf_trace_printk("%s opened file %s.\\n", comm, fname);
    return 0;
};
"""


b = BPF(text=program)
# instrumenting the sys_open call.
syscall = b.get_syscall_fnname("openat")
b.attach_kprobe(syscall, fn_name="syscall__openat")
# need to do this for the program to continue.
b.trace_print()
