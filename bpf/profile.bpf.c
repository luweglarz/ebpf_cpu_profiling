
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "profile.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, 256 * 1024);
// } sys_exec_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} perf_events SEC(".maps");

inline int collect_stack(void *ctx, void *map){

    struct stacktrace_event *event;

    // reserve a ringbuf sizeof(*event) at &events
	event = bpf_ringbuf_reserve(map, sizeof(*event), 0);
	if (!event)
		return 1;

    //Get pid/cpu_id of the calling process
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->cpu_id = bpf_get_smp_processor_id();

    //Get the comm attribute of the calling process from its task_struct
	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;

	event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);
	bpf_ringbuf_submit(event, 0);
    return 0;
}

// SEC("tp/syscalls/sys_exit_execve")
// int sys_exec(void *ctx){
// 	return collect_stack(ctx, &sys_exec_events);
// }

SEC("perf_event")
int cpu_profiling(void *ctx){
	return collect_stack(ctx, &perf_events);
}