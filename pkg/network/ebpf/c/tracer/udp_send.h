#ifndef __UDP_SEND_H
#define __UDP_SEND_H

#include "bpf_helpers.h"
#include "bpf_telemetry.h"
#include "bpf_bypass.h"

#include "tracer/stats.h"
#include "tracer/maps.h"
#include "sock.h"

#ifdef COMPILE_PREBUILT
#include "prebuilt/offsets.h"
#endif

__maybe_unused static __always_inline bool udp_send_page_enabled() {
    __u64 val = 0;
    LOAD_CONSTANT("udp_send_page_enabled", val);
    return val > 0;
}

static __always_inline u32 fl4_saddr(struct flowi4 *fl4) {
    u32 addr = 0;
#ifdef COMPILE_PREBUILT
    bpf_probe_read_kernel_with_telemetry(&addr, sizeof(addr), ((char *)fl4) + offset_saddr_fl4());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&addr, fl4, saddr);
#endif

    return addr;
}

static __always_inline u32 fl4_daddr(struct flowi4 *fl4) {
    u32 addr = 0;
#ifdef COMPILE_PREBUILT
    bpf_probe_read_kernel_with_telemetry(&addr, sizeof(addr), ((char *)fl4) + offset_daddr_fl4());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&addr, fl4, daddr);
#endif

    return addr;
}

static __always_inline u16 _fl4_sport(struct flowi4 *fl4) {
    u16 sport = 0;
#ifdef COMPILE_PREBUILT
    bpf_probe_read_kernel_with_telemetry(&sport, sizeof(sport), ((char *)fl4) + offset_sport_fl4());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&sport, fl4, fl4_sport);
#endif

    return sport;
}

static __always_inline u16 _fl4_dport(struct flowi4 *fl4) {
    u16 dport = 0;
#ifdef COMPILE_PREBUILT
    bpf_probe_read_kernel_with_telemetry(&dport, sizeof(dport), ((char *)fl4) + offset_dport_fl4());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&dport, fl4, fl4_dport);
#endif

    return dport;
}

static __always_inline int handle_ip_skb(struct sock *sk, size_t size, struct flowi4 *fl4) {
    if (size <= sizeof(struct udphdr)) {
        return 0;
    }

    size -= sizeof(struct udphdr);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_UDP)) {
#ifdef COMPILE_PREBUILT
        if (!are_fl4_offsets_known()) {
            log_debug("ERR: src/dst addr not set src:%llu,dst:%llu. fl4 offsets are not known", t.saddr_l, t.daddr_l);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }
#endif

        t.saddr_l = fl4_saddr(fl4);
        t.daddr_l = fl4_daddr(fl4);

        if (!t.saddr_l || !t.daddr_l) {
            log_debug("ERR(fl4): src/dst addr not set src:%llu,dst:%llu", t.saddr_l, t.daddr_l);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        t.sport = _fl4_sport(fl4);
        t.dport = _fl4_dport(fl4);

        if (t.sport == 0 || t.dport == 0) {
            log_debug("ERR(fl4): src/dst port not set: src:%d, dst:%d", t.sport, t.dport);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        t.sport = bpf_ntohs(t.sport);
        t.dport = bpf_ntohs(t.dport);
    }

    log_debug("kprobe/ip_make_skb: pid_tgid: %llu, size: %zu", pid_tgid, size);

    handle_message(&t, size, 0, CONN_DIRECTION_UNKNOWN, 1, 0, PACKET_COUNT_INCREMENT, sk);
    increment_telemetry_count(udp_send_processed);

    return 0;
}

SEC("kprobe/udp_sendpage")
int BPF_BYPASSABLE_KPROBE(kprobe__udp_sendpage, struct sock *skp) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("kprobe/udp_sendpage: pid_tgid: %llu", pid_tgid);
    bpf_map_update_with_telemetry(udp_sendpage_args, &pid_tgid, &skp, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_sendpage")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__udp_sendpage, int sent) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = (struct sock **)bpf_map_lookup_elem(&udp_sendpage_args, &pid_tgid);
    if (!skpp) {
        log_debug("kretprobe/udp_sendpage: sock not found");
        return 0;
    }

    struct sock *skp = *skpp;
    bpf_map_delete_elem(&udp_sendpage_args, &pid_tgid);

    if (sent < 0) {
        return 0;
    }
    if (!skp) {
        return 0;
    }

    log_debug("kretprobe/udp_sendpage: pid_tgid: %llu, sent: %d, sock: %p", pid_tgid, sent, skp);
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, skp, pid_tgid, CONN_TYPE_UDP)) {
        return 0;
    }

    return handle_message(&t, sent, 0, CONN_DIRECTION_UNKNOWN, 1, 0, PACKET_COUNT_INCREMENT, skp);
}

// Note: This is used only in the UDP send path.
SEC("kprobe/ip_make_skb")
int BPF_BYPASSABLE_KPROBE(kprobe__ip_make_skb, struct sock *sk) {
    size_t len = (size_t)PT_REGS_PARM5(ctx);
    struct flowi4 *fl4 = (struct flowi4 *)PT_REGS_PARM2(ctx);
#if defined(COMPILE_PREBUILT) || defined(COMPILE_CORE) || (defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0))
    unsigned int flags = PT_REGS_PARM10(ctx);
    if (flags & MSG_SPLICE_PAGES && udp_send_page_enabled()) {
        return 0;
    }
#endif

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ip_make_skb_args_t args = {};
    bpf_probe_read_kernel_with_telemetry(&args.sk, sizeof(args.sk), &sk);
    bpf_probe_read_kernel_with_telemetry(&args.len, sizeof(args.len), &len);
    bpf_probe_read_kernel_with_telemetry(&args.fl4, sizeof(args.fl4), &fl4);
    bpf_map_update_with_telemetry(ip_make_skb_args, &pid_tgid, &args, BPF_ANY);

    return 0;
}

SEC("kprobe/ip_make_skb")
int BPF_BYPASSABLE_KPROBE(kprobe__ip_make_skb__pre_4_18_0, struct sock *sk) {
    size_t len = (size_t)PT_REGS_PARM5(ctx);
    struct flowi4 *fl4 = (struct flowi4 *)PT_REGS_PARM2(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ip_make_skb_args_t args = {};
    bpf_probe_read_kernel_with_telemetry(&args.sk, sizeof(args.sk), &sk);
    bpf_probe_read_kernel_with_telemetry(&args.len, sizeof(args.len), &len);
    bpf_probe_read_kernel_with_telemetry(&args.fl4, sizeof(args.fl4), &fl4);
    bpf_map_update_with_telemetry(ip_make_skb_args, &pid_tgid, &args, BPF_ANY);

    return 0;
}

SEC("kretprobe/ip_make_skb")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__ip_make_skb, void *rc) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ip_make_skb_args_t *args = bpf_map_lookup_elem(&ip_make_skb_args, &pid_tgid);
    if (!args) {
        return 0;
    }

    struct sock *sk = args->sk;
    struct flowi4 *fl4 = args->fl4;
    size_t size = args->len;
    bpf_map_delete_elem(&ip_make_skb_args, &pid_tgid);

    if (IS_ERR_OR_NULL(rc)) {
        return 0;
    }

    return handle_ip_skb(sk, size, fl4);
}

#endif
