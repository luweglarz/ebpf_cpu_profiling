LOADER_SRC := ./loader.c

LOADER := loader

BPF_SRC := bpf/profile.bpf.c

BPF_OBJ := bpf/profile.bpf.o

VMLINUX := vmlinux.h

BPF_SKEL := profile.bpf.skel.h

COMP := clang

BPF_FLAGS := -O2 -g -target bpf -Wall -Werror -Wunused -Wextra

LOADER_FLAGS := -lbpf 

all: $(BPF_OBJ) $(LOADER)

clean:
	rm -f $(BPF_OBJ) $(LOADER) bpf/$(BPF_SKEL)

re: clean

$(LOADER):$(BPF_SKEL)
	@echo "Compiling user_space program"
	$(COMP) $(LOADER_FLAGS) $(LOADER_SRC) -o $(LOADER)

$(BPF_OBJ):
	@echo "Compiling eBPF program"
	$(COMP) $(BPF_FLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

$(BPF_SKEL):$(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > bpf/$(BPF_SKEL)