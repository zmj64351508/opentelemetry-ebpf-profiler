//go:build linux
// +build linux

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracer

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/rlimit"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/util"

	"golang.org/x/sys/unix"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// ProbeBPFSyscall checks if the syscall EBPF is available on the system.
func ProbeBPFSyscall() error {
	_, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(unix.BPF_PROG_TYPE_UNSPEC), uintptr(0), 0)
	if errNo == unix.ENOSYS {
		return errors.New("eBPF syscall is not available on your system")
	}
	return nil
}

// getTracepointID returns the system specific tracepoint ID for a given tracepoint.
func getTracepointID(tracepoint string) (uint64, error) {
	id, err := os.ReadFile("/sys/kernel/debug/tracing/events/syscalls/" + tracepoint + "/id")
	if err != nil {
		return 0, fmt.Errorf("failed to read tracepoint ID for %s: %v", tracepoint, err)
	}
	tid := util.DecToUint64(strings.TrimSpace(string(id)))
	return tid, nil
}

// GetCurrentKernelVersion returns the major, minor and patch version of the kernel of the host
// from the utsname struct.
func GetCurrentKernelVersion() (major, minor, patch uint32, err error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return 0, 0, 0, fmt.Errorf("could not get Kernel Version: %v", err)
	}
	_, _ = fmt.Fscanf(bytes.NewReader(uname.Release[:]), "%d.%d.%d", &major, &minor, &patch)
	return major, minor, patch, nil
}

// ProbeTracepoint checks if tracepoints are available on the system, so we can attach
// our eBPF code there.
func ProbeTracepoint() error {
	ins := asm.Instructions{
		// set exit code to 0
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// The check of the kernel version was removed with
	// commit 6c4fc209fcf9d27efbaa48368773e4d2bfbd59aa. So kernel < 4.20
	// need to set the kernel version to not be rejected by the verifier.
	major, minor, patch, err := GetCurrentKernelVersion()
	if err != nil {
		return err
	}
	kernelVersion := util.VersionUint(major, minor, patch)
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("failed to increase rlimit: %v", err)
	}
	defer restoreRlimit()

	prog, err := cebpf.NewProgram(&cebpf.ProgramSpec{
		Type:          cebpf.TracePoint,
		License:       "GPL",
		Instructions:  ins,
		KernelVersion: kernelVersion,
	})
	if err != nil {
		return fmt.Errorf("failed to create tracepoint_probe: %v", err)
	}
	defer prog.Close()
	return nil
}
