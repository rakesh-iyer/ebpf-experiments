#!/usr/bin/python3

# this framework allows high level orchestration of berkeley packet filter handlers
from bcc import BPF

# define the ebpf program.
program = """
#include <uapi/linux/ptrace.h>

int hello(struct pt_regs *ctx) {
    char parent[200];
    // path is the 2nd argument?
    char *child_path = (char *)PT_REGS_PARM2(ctx);
    bpf_get_current_comm(parent, 200);
    bpf_trace_printk("A program %s was executed from %s.\\n", child_path, parent);
    return 0; 
}
"""


b = BPF(text=program)

# instrumenting the execve system call
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
b.trace_print()
