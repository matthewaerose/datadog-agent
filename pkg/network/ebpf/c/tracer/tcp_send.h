#ifndef __TCP_SEND_H
#define __TCP_SEND_H

#include "bpf_helpers.h"
#include "bpf_telemetry.h"
#include "bpf_bypass.h"

#include "tracer/stats.h"
#include "tracer/maps.h"
#include "sock.h"

SEC("kprobe/tcp_sendmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_sendmsg) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("kprobe/tcp_sendmsg: pid_tgid: %llu", pid_tgid);
#if defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
    struct sock *skp = (struct sock *)PT_REGS_PARM2(ctx);
#else
    struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);
#endif
    log_debug("kprobe/tcp_sendmsg: pid_tgid: %llu, sock: %p", pid_tgid, skp);
    bpf_map_update_with_telemetry(tcp_sendmsg_args, &pid_tgid, &skp, BPF_ANY);

    return 0;
}

#if defined(COMPILE_CORE) || defined(COMPILE_PREBUILT)
SEC("kprobe/tcp_sendmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_sendmsg__pre_4_1_0) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("kprobe/tcp_sendmsg: pid_tgid: %llu", pid_tgid);
    struct sock *skp = (struct sock *)PT_REGS_PARM2(ctx);
    bpf_map_update_with_telemetry(tcp_sendmsg_args, &pid_tgid, &skp, BPF_ANY);
    return 0;
}
#endif

SEC("kretprobe/tcp_sendmsg")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__tcp_sendmsg, int sent) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = (struct sock **)bpf_map_lookup_elem(&tcp_sendmsg_args, &pid_tgid);
    if (!skpp) {
        log_debug("kretprobe/tcp_sendmsg: sock not found");
        return 0;
    }

    struct sock *skp = *skpp;
    bpf_map_delete_elem(&tcp_sendmsg_args, &pid_tgid);

    if (sent < 0) {
        return 0;
    }

    if (!skp) {
        return 0;
    }

    log_debug("kretprobe/tcp_sendmsg: pid_tgid: %llu, sent: %d, sock: %p", pid_tgid, sent, skp);
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, skp, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    handle_tcp_stats(&t, skp, 0);

    __u32 packets_in = 0;
    __u32 packets_out = 0;
    get_tcp_segment_counts(skp, &packets_in, &packets_out);

    return handle_message(&t, sent, 0, CONN_DIRECTION_UNKNOWN, packets_out, packets_in, PACKET_COUNT_ABSOLUTE, skp);
}

SEC("kprobe/tcp_sendpage")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_sendpage) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("kprobe/tcp_sendpage: pid_tgid: %llu", pid_tgid);
    struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);
    bpf_map_update_with_telemetry(tcp_sendpage_args, &pid_tgid, &skp, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_sendpage")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__tcp_sendpage, int sent) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = (struct sock **)bpf_map_lookup_elem(&tcp_sendpage_args, &pid_tgid);
    if (!skpp) {
        log_debug("kretprobe/tcp_sendpage: sock not found");
        return 0;
    }

    struct sock *skp = *skpp;
    bpf_map_delete_elem(&tcp_sendpage_args, &pid_tgid);

    if (sent < 0) {
        return 0;
    }

    if (!skp) {
        return 0;
    }

    log_debug("kretprobe/tcp_sendpage: pid_tgid: %llu, sent: %d, sock: %p", pid_tgid, sent, skp);
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, skp, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    handle_tcp_stats(&t, skp, 0);

    __u32 packets_in = 0;
    __u32 packets_out = 0;
    get_tcp_segment_counts(skp, &packets_in, &packets_out);

    return handle_message(&t, sent, 0, CONN_DIRECTION_UNKNOWN, packets_out, packets_in, PACKET_COUNT_ABSOLUTE, skp);
}

#endif
