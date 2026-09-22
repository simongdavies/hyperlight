// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/keyctl.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void expect_denied(const char *name, long result, int expected)
{
    int error = errno;
    if (result > 0) {
        int status;
        while (waitpid((pid_t)result, &status, 0) < 0 && errno == EINTR) {}
    }
    if (result != -1 || error != expected) {
        fprintf(stderr, "%s: result=%ld errno=%d expected=%d\n",
                name, result, error, expected);
        exit(2);
    }
    printf("%s denied errno=%d\n", name, error);
}

static void check_key_access(void)
{
    expect_denied("keyctl",
                  syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID,
                          KEY_SPEC_SESSION_KEYRING, 0), EPERM);
    expect_denied("add_key",
                  syscall(SYS_add_key, "user", "hyperlight-probe", "probe", 5,
                          KEY_SPEC_SESSION_KEYRING), EPERM);
    expect_denied("request_key",
                  syscall(SYS_request_key, "user", "hyperlight-probe", NULL,
                          KEY_SPEC_SESSION_KEYRING), EPERM);
}

#ifndef HYPERLIGHT_BASELINE_PROBE
static int exit_child(void *unused)
{
    (void)unused;
    return 99;
}

static void check_process_creation(void)
{
    long result;
#ifdef SYS_fork
    result = syscall(SYS_fork);
    if (result == 0)
        _exit(99);
    expect_denied("fork syscall", result, EPERM);
#endif
    result = vfork();
    if (result == 0)
        _exit(99);
    expect_denied("vfork", result, EPERM);

    char stack[65536] __attribute__((aligned(16)));
    const int flags[] = {SIGCHLD, CLONE_VM | SIGCHLD,
                        CLONE_VM | CLONE_VFORK | SIGCHLD};
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
        result = clone(exit_child, stack + sizeof(stack), flags[i], NULL);
        expect_denied("clone process", result, EPERM);
    }
    struct clone_args args = {.exit_signal = SIGCHLD};
    result = syscall(SYS_clone3, &args, sizeof(args));
    if (result == 0)
        _exit(99);
    expect_denied("clone3 process", result, ENOSYS);
}
#endif

static void check_restrictions(void)
{
    check_key_access();
#ifndef HYPERLIGHT_BASELINE_PROBE
    check_process_creation();
#endif
}

static void *check_thread(void *unused)
{
    (void)unused;
    check_restrictions();
    return NULL;
}

int main(void)
{
    puts("WORKLOAD_EXECUTED");
    fflush(stdout);
    char ipc_namespace[128];
    ssize_t length = readlink("/proc/self/ns/ipc", ipc_namespace,
                             sizeof(ipc_namespace) - 1);
    if (length < 0 || (size_t)length >= sizeof(ipc_namespace) - 1) {
        fputs("Cannot read IPC namespace identity\n", stderr);
        return 2;
    }
    ipc_namespace[length] = '\0';
    printf("IPC_NAMESPACE=%s\n", ipc_namespace);
    check_restrictions();
    pthread_t thread;
    int error = pthread_create(&thread, NULL, check_thread, NULL);
    if (error != 0 || (error = pthread_join(thread, NULL)) != 0) {
        fprintf(stderr, "pthread create/join: %d\n", error);
        return 2;
    }
    expect_denied("disable seccomp", prctl(PR_SET_SECCOMP, 0, 0), EINVAL);
    struct sock_filter allow = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog filter = {.len = 1, .filter = &allow};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter) != 0) {
        perror("stack permissive filter");
        return 2;
    }
    check_restrictions();
    if (access("/process-filter", F_OK) != -1 || errno != ENOENT) {
        fputs("Private filter is visible in workload root\n", stderr);
        return 2;
    }
    puts("KEY_POLICY_OK");
#ifndef HYPERLIGHT_BASELINE_PROBE
    puts("CHILD_POLICY_OK");
#endif
    return 0;
}
