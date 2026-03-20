#ifndef __UDPV6_H
#define __UDPV6_H

#include "bpf_helpers.h"
#include "bpf_telemetry.h"
#include "bpf_bypass.h"

#include "tracer/stats.h"
#include "tracer/maps.h"
#include "sock.h"

#ifdef COMPILE_PREBUILT
#include "prebuilt/offsets.h"
#endif

#if !defined(COMPILE_RUNTIME) || defined(FEATURE_UDPV6_ENABLED)

static __always_inline void fl6_saddr(struct flowi6 *fl6, u64 *addr_h, u64 *addr_l) {
    if (!fl6 || !addr_h || !addr_l) {
        return;
    }

    struct in6_addr in6 = {};
#ifdef COMPILE_PREBUILT
    bpf_probe_read_kernel_with_telemetry(&in6, sizeof(in6), ((char *)fl6) + offset_saddr_fl6());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&in6, fl6, saddr);
#endif
    read_in6_addr(addr_h, addr_l, &in6);
}

static __always_inline void fl6_daddr(struct flowi6 *fl6, u64 *addr_h, u64 *addr_l) {
    if (!fl6 || !addr_h || !addr_l) {
        return;
    }

    struct in6_addr in6 = {};
#ifdef COMPILE_PREBUILT
    bpf_probe_read_kernel_with_telemetry(&in6, sizeof(in6), ((char *)fl6) + offset_daddr_fl6());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&in6, fl6, daddr);
#endif
    read_in6_addr(addr_h, addr_l, &in6);
}

static __always_inline u16 _fl6_sport(struct flowi6 *fl6) {
    u16 sport = 0;
#ifdef COMPILE_PREBUILT
    bpf_probe_read_kernel_with_telemetry(&sport, sizeof(sport), ((char *)fl6) + offset_sport_fl6());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&sport, fl6, fl6_sport);
#endif

    return sport;
}

static __always_inline u16 _fl6_dport(struct flowi6 *fl6) {
    u16 dport = 0;
#ifdef COMPILE_PREBUILT
    bpf_probe_read_kernel_with_telemetry(&dport, sizeof(dport), ((char *)fl6) + offset_dport_fl6());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&dport, fl6, fl6_dport);
#endif

    return dport;
}

static __always_inline int handle_ip6_skb(struct sock *sk, size_t size, struct flowi6 *fl6) {
    if (size <= sizeof(struct udphdr)) {
        return 0;
    }

    size -= sizeof(struct udphdr);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_UDP)) {
#ifdef COMPILE_PREBUILT
        if (!are_fl6_offsets_known()) {
            log_debug("ERR: src/dst addr not set, fl6 offsets are not known");
            increment_telemetry_count(udp_send_missed);
            return 0;
        }
#endif
        fl6_saddr(fl6, &t.saddr_h, &t.saddr_l);
        if (!(t.saddr_h || t.saddr_l)) {
            log_debug("ERR(fl6): src addr not set src_l:%llu,src_h:%llu", t.saddr_l, t.saddr_h);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        fl6_daddr(fl6, &t.daddr_h, &t.daddr_l);
        if (!(t.daddr_h || t.daddr_l)) {
            log_debug("ERR(fl6): dst addr not set dst_l:%llu,dst_h:%llu", t.daddr_l, t.daddr_h);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        // Check if we can map IPv6 to IPv4
        if (is_ipv4_mapped_ipv6(t.saddr_h, t.saddr_l, t.daddr_h, t.daddr_l)) {
            t.metadata |= CONN_V4;
            t.saddr_h = 0;
            t.daddr_h = 0;
            t.saddr_l = (u32)(t.saddr_l >> 32);
            t.daddr_l = (u32)(t.daddr_l >> 32);
        } else {
            t.metadata |= CONN_V6;
        }

        t.sport = _fl6_sport(fl6);
        t.dport = _fl6_dport(fl6);

        if (t.sport == 0 || t.dport == 0) {
            log_debug("ERR(fl6): src/dst port not set: src:%d, dst:%d", t.sport, t.dport);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        t.sport = bpf_ntohs(t.sport);
        t.dport = bpf_ntohs(t.dport);
    }

    log_debug("kprobe/ip6_make_skb: pid_tgid: %llu, size: %zu", pid_tgid, size);
    handle_message(&t, size, 0, CONN_DIRECTION_UNKNOWN, 1, 0, PACKET_COUNT_INCREMENT, sk);
    increment_telemetry_count(udp_send_processed);

    return 0;
}

#if defined(COMPILE_CORE) || defined(COMPILE_PREBUILT)
// commit: https://github.com/torvalds/linux/commit/26879da58711aa604a1b866cbeedd7e0f78f90ad
// changed the arguments to ip6_make_skb and introduced the struct ipcm6_cookie
SEC("kprobe/ip6_make_skb")
int BPF_BYPASSABLE_KPROBE(kprobe__ip6_make_skb__pre_4_7_0, struct sock *sk) {
    size_t len = (size_t)PT_REGS_PARM4(ctx);
    struct flowi6 *fl6 = (struct flowi6 *)PT_REGS_PARM9(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ip_make_skb_args_t args = {};
    bpf_probe_read_kernel_with_telemetry(&args.sk, sizeof(args.sk), &sk);
    bpf_probe_read_kernel_with_telemetry(&args.len, sizeof(args.len), &len);
    bpf_probe_read_kernel_with_telemetry(&args.fl6, sizeof(args.fl6), &fl6);
    bpf_map_update_with_telemetry(ip_make_skb_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kprobe/ip6_make_skb")
int BPF_BYPASSABLE_KPROBE(kprobe__ip6_make_skb__pre_5_18_0, struct sock *sk) {
    size_t len = (size_t)PT_REGS_PARM4(ctx);
    struct flowi6 *fl6 = (struct flowi6 *)PT_REGS_PARM7(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ip_make_skb_args_t args = {};
    bpf_probe_read_kernel_with_telemetry(&args.sk, sizeof(args.sk), &sk);
    bpf_probe_read_kernel_with_telemetry(&args.len, sizeof(args.len), &len);
    bpf_probe_read_kernel_with_telemetry(&args.fl6, sizeof(args.fl6), &fl6);
    bpf_map_update_with_telemetry(ip_make_skb_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

#endif // COMPILE_CORE || COMPILE_PREBUILT

#if defined(COMPILE_RUNTIME) || defined(COMPILE_CORE)

SEC("kprobe/ip6_make_skb")
int BPF_BYPASSABLE_KPROBE(kprobe__ip6_make_skb, struct sock *sk) {
    size_t len = (size_t)PT_REGS_PARM4(ctx);
#if defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
    // commit: https://github.com/torvalds/linux/commit/f37a4cc6bb0ba08c2d9fd7d18a1da87161cbb7f9
    struct inet_cork_full *cork_full = (struct inet_cork_full *)PT_REGS_PARM9(ctx);
    struct flowi6 *fl6 = &cork_full->fl.u.ip6;
#elif defined(COMPILE_CORE)
    struct inet_cork_full *cork_full = (struct inet_cork_full *)PT_REGS_PARM9(ctx);
    struct flowi6 *fl6 = (struct flowi6 *)__builtin_preserve_access_index(&cork_full->fl.u.ip6);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
    // commit: https://github.com/torvalds/linux/commit/26879da58711aa604a1b866cbeedd7e0f78f90ad
    // changed the arguments to ip6_make_skb and introduced the struct ipcm6_cookie
    struct flowi6 *fl6 = (struct flowi6 *)PT_REGS_PARM7(ctx);
#else
    struct flowi6 *fl6 = (struct flowi6 *)PT_REGS_PARM9(ctx);
#endif

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ip_make_skb_args_t args = {};
    bpf_probe_read_kernel_with_telemetry(&args.sk, sizeof(args.sk), &sk);
    bpf_probe_read_kernel_with_telemetry(&args.len, sizeof(args.len), &len);
    bpf_probe_read_kernel_with_telemetry(&args.fl6, sizeof(args.fl6), &fl6);
    bpf_map_update_with_telemetry(ip_make_skb_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

#endif // COMPILE_RUNTIME || COMPILE_CORE

SEC("kretprobe/ip6_make_skb")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__ip6_make_skb, void *rc) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ip_make_skb_args_t *args = bpf_map_lookup_elem(&ip_make_skb_args, &pid_tgid);
    if (!args) {
        return 0;
    }

    struct sock *sk = args->sk;
    struct flowi6 *fl6 = args->fl6;
    size_t size = args->len;
    bpf_map_delete_elem(&ip_make_skb_args, &pid_tgid);

    if (IS_ERR_OR_NULL(rc)) {
        return 0;
    }

    return handle_ip6_skb(sk, size, fl6);
}

#endif // !COMPILE_RUNTIME || FEATURE_UDPV6_ENABLED

#endif
