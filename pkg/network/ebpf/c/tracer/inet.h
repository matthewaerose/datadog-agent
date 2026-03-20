#ifndef __INET_H
#define __INET_H

#include "bpf_helpers.h"
#include "bpf_telemetry.h"
#include "bpf_bypass.h"

#include "tracer/bind.h"

SEC("kprobe/inet_bind")
int BPF_BYPASSABLE_KPROBE(kprobe__inet_bind, struct socket *sock, struct sockaddr *addr) {
    log_debug("kprobe/inet_bind: sock=%p, umyaddr=%p", sock, addr);
    return sys_enter_bind(sock, addr);
}

SEC("kprobe/inet6_bind")
int BPF_BYPASSABLE_KPROBE(kprobe__inet6_bind, struct socket *sock, struct sockaddr *addr) {
    log_debug("kprobe/inet6_bind: sock=%p, umyaddr=%p", sock, addr);
    return sys_enter_bind(sock, addr);
}

SEC("kretprobe/inet_bind")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__inet_bind, __s64 ret) {
    log_debug("kretprobe/inet_bind: ret=%lld", ret);
    return sys_exit_bind(ret);
}

SEC("kretprobe/inet6_bind")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__inet6_bind, __s64 ret) {
    log_debug("kretprobe/inet6_bind: ret=%lld", ret);
    return sys_exit_bind(ret);
}

#endif
