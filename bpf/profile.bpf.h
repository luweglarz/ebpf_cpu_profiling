#ifndef EXECVE_PROFILER_H
#define EXECVE_PROFILER_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 127
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

// Custom stacktrace_event struct
struct stacktrace_event {
	__u32 pid;
	__u32 cpu_id;
	char comm[TASK_COMM_LEN];
	__s32 kstack_sz;
	__s32 ustack_sz;
	stack_trace_t kstack;
	stack_trace_t ustack;
};

#endif