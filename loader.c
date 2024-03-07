
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include "bpf/profile.bpf.skel.h"
#include "bpf/profile.bpf.h"
#include "blazesym.h"

static struct blaze_symbolizer *symbolizer;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

static int parse_online_cpu(int **online_cpus){
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	int fd = open(online_cpus_file, O_RDONLY | O_CLOEXEC);
	char buf[128];
	int i = 0, err = -1, read_len = 0, scan_len = 0, range = 0;
	int start = 0, end = 0;

	if ((read_len = read(fd, buf, sizeof(buf))) <= 0)
		return 1;
	buf[read_len] = '\0';
	while (buf[i]){
		range = 0;
		if (buf[i] == ','){
			i += 1;
			continue;
		}
		err = sscanf(buf + i, "%d%n-%d%n", &start, &scan_len, &end, &scan_len);
		if (err <= 0 || err > 2)
			return 1;
		range = end - start + 1;
		for (; start < end; start++)
			(*online_cpus)[start] = start;
		(*online_cpus)[start] = end;
		i += scan_len;
	}
	return err;
}

static void print_stack(pid_t pid, __u64 *stack, __s32 stack_sz){
	const struct blaze_result *result;
	const struct blaze_sym *sym;
	int i, j;

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};
		result = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};
		result = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}

	for (i = 0; i < stack_sz / 8; i++) {

    	sym = &result->syms[i];
		printf("symbol: %s\n", sym->name);
	}
}

static int event_handler(void *_ctx, void *data, size_t size)
{
	struct stacktrace_event *event = data;

	if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
		return 1;

	printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);

	if (event->kstack_sz > 0) {
		printf("Kernel: %d\n", event->kstack_sz);
		print_stack(0, event->kstack, event->kstack_sz);
		// for (int i = 0; i < event->kstack_sz / 8; i++) 
		// 	printf("  %d [<%016llx>]\n", i, event->kstack[i]);
	} else {
		printf("No Kernel Stack\n");
	}

	if (event->ustack_sz > 0) {
		printf("Userspace: %d\n", event->ustack_sz);
		print_stack(event->pid, event->ustack, event->ustack_sz);
		// for (int i = 0; i < event->ustack_sz / 8; i++) 
		// 	printf("  %d [<%016llx>]\n", i, event->ustack[i]);
	} else {
		printf("No Userspace Stack\n");
	}

	printf("\n");
	return 0;
}

int main(){
	struct profile_bpf *skel = NULL;
	struct bpf_link *sys_exec_link = NULL, *cpu_profiling_link = NULL;
	struct bpf_link **links = NULL;
	struct ring_buffer *ring_buf = NULL;
	struct perf_event_attr attr;
	int pid = -1;
	int *pefds = NULL, pefd;
	int max_cpus = libbpf_num_possible_cpus() + 20;
	int *online_cpus = NULL;
	int err;

	online_cpus = malloc(sizeof(int) * max_cpus);
	if (online_cpus == NULL){
		fprintf(stderr, "Malloc failed\n");
		goto cleanup;
	}
	memset(online_cpus, -1, sizeof(int) * max_cpus);
	err = parse_online_cpu(&online_cpus);
	if (err == -1) {
		fprintf(stderr, "Fail to get online CPU numbers: %d\n", err);
		goto cleanup;
	}

	skel = profile_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Fail to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.perf_events), event_handler, NULL, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}

	pefds = malloc(max_cpus * sizeof(int));
	for (int i = 0; i < max_cpus; i++) {
		pefds[i] = -1;
	}

	links = calloc(max_cpus, sizeof(struct bpf_link *));

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_SW_TASK_CLOCK;
	//Hard coded frequency
	attr.sample_freq = 10;
	attr.freq = 1;

	for (int i = 0; i < max_cpus; i++){
	 	if (online_cpus[i] == -1)
	 		continue;
		pefd = perf_event_open(&attr, pid, online_cpus[i], -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			fprintf(stderr, "Fail to set up performance monitor on a CPU/Core %d\n", pefd);
			err = -1;
			goto cleanup;
		}
		pefds[online_cpus[i]] = pefd;

		links[online_cpus[i]] = bpf_program__attach_perf_event(skel->progs.cpu_profiling, pefd);
		if (!links[online_cpus[i]]) {
			err = -1;
			goto cleanup;
		}
	}

	while (ring_buffer__poll(ring_buf, -1) >= 0) {
	}

cleanup:
	if (links) {
		for (int i = 0; i < max_cpus; i++){
			if (online_cpus[i] > -1)
				bpf_link__destroy(links[online_cpus[i]]);
		free(links);
		}
	}
	if (pefds) {
		for (int i = 0; i < max_cpus; i++) {
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}
	ring_buffer__free(ring_buf);
	profile_bpf__destroy(skel);
	free(online_cpus);
	return -err;

}
