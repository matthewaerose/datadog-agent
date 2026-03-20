#ifndef __UDP_RECV_H
#define __UDP_RECV_H

#include "bpf_helpers.h"
#include "bpf_telemetry.h"
#include "bpf_bypass.h"

#include "tracer/stats.h"
#include "tracer/maps.h"
#include "sock.h"

#define handle_udp_recvmsg(sk, msg, flags, udp_sock_map)                                                 \
    do {                                                                                                 \
        log_debug("kprobe/udp_recvmsg: flags: %x", flags);                                               \
        if (flags & MSG_PEEK) {                                                                          \
            return 0;                                                                                    \
        }                                                                                                \
                                                                                                         \
        /* keep track of non-peeking calls, since skb_free_datagram_locked doesn't have that argument */ \
        u64 pid_tgid = bpf_get_current_pid_tgid();                                                       \
        udp_recv_sock_t t = { .sk = sk, .msg = msg };                                                    \
        bpf_map_update_with_telemetry(udp_sock_map, &pid_tgid, &t, BPF_ANY);                             \
        return 0;                                                                                        \
    } while (0);

SEC("kprobe/udp_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__udp_recvmsg) {
#if defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
    int flags = (int)PT_REGS_PARM6(ctx);
#elif defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
    int flags = (int)PT_REGS_PARM5(ctx);
#else
    int flags = (int)PT_REGS_PARM4(ctx);
#endif
    struct sock *sk = NULL;
    struct msghdr *msg = NULL;
    handle_udp_recvmsg(sk, msg, flags, udp_recv_sock);
}

#if !defined(COMPILE_RUNTIME) || defined(FEATURE_UDPV6_ENABLED)
SEC("kprobe/udpv6_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__udpv6_recvmsg) {
#if defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
    int flags = (int)PT_REGS_PARM6(ctx);
#elif defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
    int flags = (int)PT_REGS_PARM5(ctx);
#else
    int flags = (int)PT_REGS_PARM4(ctx);
#endif
    struct sock *sk = NULL;
    struct msghdr *msg = NULL;
    handle_udp_recvmsg(sk, msg, flags, udp_recv_sock);
}
#endif // !COMPILE_RUNTIME || defined(FEATURE_UDPV6_ENABLED)

static __always_inline int handle_udp_recvmsg_ret() {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&udp_recv_sock, &pid_tgid);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__udp_recvmsg) {
    return handle_udp_recvmsg_ret();
}

#if !defined(COMPILE_RUNTIME) || defined(FEATURE_UDPV6_ENABLED)
SEC("kretprobe/udpv6_recvmsg")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__udpv6_recvmsg) {
    return handle_udp_recvmsg_ret();
}
#endif // !COMPILE_RUNTIME || defined(FEATURE_UDPV6_ENABLED)

#if defined(COMPILE_CORE) || defined(COMPILE_PREBUILT)

static __always_inline int handle_ret_udp_recvmsg_pre_4_7_0(int copied, void *udp_sock_map) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("kretprobe/udp_recvmsg: kernel thread id: %llu, user mode pid: %llu", GET_KERNEL_THREAD_ID(pid_tgid), GET_USER_MODE_PID(pid_tgid));

    // Retrieve socket pointer from kprobe via pid/tgid
    udp_recv_sock_t *st = bpf_map_lookup_elem(udp_sock_map, &pid_tgid);
    if (!st) { // Missed entry
        return 0;
    }

    if (copied < 0) { // Non-zero values are errors (or a peek) (e.g -EINVAL)
        log_debug("kretprobe/udp_recvmsg: ret=%d < 0, pid_tgid=%llu", copied, pid_tgid);
        // Make sure we clean up the key
        bpf_map_delete_elem(udp_sock_map, &pid_tgid);
        return 0;
    }

    log_debug("kretprobe/udp_recvmsg: ret=%d", copied);

    conn_tuple_t t = {};
    bpf_memset(&t, 0, sizeof(conn_tuple_t));
    if (st->msg) {
        struct sockaddr *sap = NULL;
        bpf_probe_read_kernel_with_telemetry(&sap, sizeof(sap), &(st->msg->msg_name));
        sockaddr_to_addr(sap, &t.daddr_h, &t.daddr_l, &t.dport, &t.metadata);
    }

    if (!read_conn_tuple_partial(&t, st->sk, pid_tgid, CONN_TYPE_UDP)) {
        log_debug("ERR(kretprobe/udp_recvmsg): error reading conn tuple, pid_tgid=%llu", pid_tgid);
        bpf_map_delete_elem(udp_sock_map, &pid_tgid);
        return 0;
    }
    bpf_map_delete_elem(udp_sock_map, &pid_tgid);

    log_debug("kretprobe/udp_recvmsg: pid_tgid: %llu, return: %d", pid_tgid, copied);
    handle_message(&t, 0, copied, CONN_DIRECTION_UNKNOWN, 0, 1, PACKET_COUNT_INCREMENT, st->sk);

    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__udp_recvmsg_pre_5_19_0) {
    struct sock *sk = NULL;
    struct msghdr *msg = NULL;
    int flags = (int)PT_REGS_PARM5(ctx);
    handle_udp_recvmsg(sk, msg, flags, udp_recv_sock);
}

SEC("kprobe/udpv6_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__udpv6_recvmsg_pre_5_19_0) {
    struct sock *sk = NULL;
    struct msghdr *msg = NULL;
    int flags = (int)PT_REGS_PARM5(ctx);
    handle_udp_recvmsg(sk, msg, flags, udp_recv_sock);
}

SEC("kprobe/udp_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__udp_recvmsg_pre_4_7_0, struct sock *sk, struct msghdr *msg) {
    int flags = (int)PT_REGS_PARM5(ctx);
    handle_udp_recvmsg(sk, msg, flags, udp_recv_sock);
}

SEC("kprobe/udpv6_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__udpv6_recvmsg_pre_4_7_0, struct sock *sk, struct msghdr *msg) {
    int flags = (int)PT_REGS_PARM5(ctx);
#ifdef COMPILE_CORE
    // on CO-RE we use only use the map to check if the
    // receive was a peek, since we the use the kprobes
    // on `skb_consume_udp` (and alternatives). These
    // kprobes explicitly check the `udp_recv_sock` map
    handle_udp_recvmsg(sk, msg, flags, udp_recv_sock);
#else
    handle_udp_recvmsg(sk, msg, flags, udpv6_recv_sock);
#endif
}

SEC("kprobe/udp_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__udp_recvmsg_pre_4_1_0) {
    struct sock *sk = (struct sock *)PT_REGS_PARM2(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM3(ctx);
    int flags = (int)PT_REGS_PARM6(ctx);
    handle_udp_recvmsg(sk, msg, flags, udp_recv_sock);
}

SEC("kprobe/udpv6_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__udpv6_recvmsg_pre_4_1_0) {
    struct sock *sk = (struct sock *)PT_REGS_PARM2(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM3(ctx);
    int flags = (int)PT_REGS_PARM6(ctx);
#ifdef COMPILE_CORE
    // on CO-RE we use only use the map to check if the
    // receive was a peek, since we the use the kprobes
    // on `skb_consume_udp` (and alternatives). These
    // kprobes explicitly check the `udp_recv_sock` map
    handle_udp_recvmsg(sk, msg, flags, udp_recv_sock);
#else
    handle_udp_recvmsg(sk, msg, flags, udpv6_recv_sock);
#endif
}

SEC("kretprobe/udp_recvmsg")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__udp_recvmsg_pre_4_7_0, int copied) {
    return handle_ret_udp_recvmsg_pre_4_7_0(copied, &udp_recv_sock);
}

SEC("kretprobe/udpv6_recvmsg")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__udpv6_recvmsg_pre_4_7_0, int copied) {
    return handle_ret_udp_recvmsg_pre_4_7_0(copied, &udpv6_recv_sock);
}

#endif // COMPILE_CORE || COMPILE_PREBUILT

SEC("kprobe/skb_free_datagram_locked")
int BPF_BYPASSABLE_KPROBE(kprobe__skb_free_datagram_locked, struct sock *sk, struct sk_buff *skb) {
    return handle_skb_consume_udp(sk, skb, 0);
}

SEC("kprobe/__skb_free_datagram_locked")
int BPF_BYPASSABLE_KPROBE(kprobe____skb_free_datagram_locked, struct sock *sk, struct sk_buff *skb, int len) {
    return handle_skb_consume_udp(sk, skb, len);
}

SEC("kprobe/skb_consume_udp")
int BPF_BYPASSABLE_KPROBE(kprobe__skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len) {
    return handle_skb_consume_udp(sk, skb, len);
}

#endif
