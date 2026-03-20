#ifndef __UDP_H
#define __UDP_H

#include "bpf_helpers.h"
#include "bpf_telemetry.h"
#include "bpf_bypass.h"

#include "tracer/stats.h"
#include "tracer/maps.h"
#include "sock.h"
#include "port.h"

static __always_inline int handle_udp_destroy_sock(void *ctx, struct sock *skp) {
    conn_tuple_t tup = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int valid_tuple = read_conn_tuple(&tup, skp, pid_tgid, CONN_TYPE_UDP);

    __u16 lport = 0;
    if (valid_tuple) {
        cleanup_conn(ctx, &tup, skp);
        lport = tup.sport;
    } else {
        lport = read_sport(skp);
    }

    if (lport == 0) {
        log_debug("ERR(udp_destroy_sock): lport is 0");
        return 0;
    }

    port_binding_t pb = {};
    pb.netns = get_netns_from_sock(skp);
    pb.port = lport;
    remove_port_bind(&pb, &udp_port_bindings);
    return 0;
}

SEC("kprobe/udp_destroy_sock")
int BPF_BYPASSABLE_KPROBE(kprobe__udp_destroy_sock, struct sock *sk) {
    return handle_udp_destroy_sock(ctx, sk);
}

SEC("kprobe/udpv6_destroy_sock")
int BPF_BYPASSABLE_KPROBE(kprobe__udpv6_destroy_sock, struct sock *sk) {
    return handle_udp_destroy_sock(ctx, sk);
}

SEC("kretprobe/udp_destroy_sock")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__udp_destroy_sock) {
    flush_conn_close_if_full(ctx);
    return 0;
}

SEC("kretprobe/udpv6_destroy_sock")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__udpv6_destroy_sock) {
    flush_conn_close_if_full(ctx);
    return 0;
}

#endif
