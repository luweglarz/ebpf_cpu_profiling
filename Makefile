LOADER_SRC := ./loader.c

LOADER := loader

BPF_SRC := bpf/profile.bpf.c

BPF_OBJ := bpf/profile.bpf.o

VMLINUX := vmlinux.h

BPF_SKEL := profile.bpf.skel.h

COMP := clang

BPF_FLAGS := -O2 -g -target bpf -Wall -Werror -Wunused -Wextra

LOADER_FLAGS := -lbpf 

BLAZESYM_INCLUDE = third-party/blazesym/capi/include

BLAZESYM_LIB = third-party/blazesym/target/debug/libblazesym_c.a

BLAZESYM_FLAGS = -lrt -ldl -lpthread -lm

all: $(BPF_OBJ) $(LOADER)

clean:
	rm -f $(BPF_OBJ) $(LOADER) bpf/$(BPF_SKEL)
	cargo clean --manifest-path third-party/blazesym/capi/Cargo.toml

re: clean all

$(LOADER):$(BPF_SKEL) $(BLAZESYM_LIB)
	@echo "Compiling user_space program"
	$(COMP) -I$(BLAZESYM_INCLUDE) $(BLAZESYM_FLAGS) $(LOADER_FLAGS) $(LOADER_SRC) -o $(LOADER) $(BLAZESYM_LIB)

$(BLAZESYM_LIB):
	cargo build --manifest-path third-party/blazesym/capi/Cargo.toml
	

$(BPF_OBJ):
	@echo "Compiling eBPF program"
	$(COMP) $(BPF_FLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

$(BPF_SKEL):$(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > bpf/$(BPF_SKEL)