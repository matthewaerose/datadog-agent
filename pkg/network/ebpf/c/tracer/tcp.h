#ifndef __TCP_H
#define __TCP_H

#include "bpf_helpers.h"
#include "bpf_telemetry.h"
#include "bpf_bypass.h"

#include "tracer/stats.h"
#include "tracer/maps.h"
#include "tracer/telemetry.h"
#include "tracer/port.h"
#include "sock.h"
#include "pid_tgid.h"

#ifdef COMPILE_PREBUILT
#include "prebuilt/offsets.h"
#endif

SEC("kprobe/tcp_done")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_done, struct sock *sk) {
    conn_tuple_t t = {};

    if (!read_conn_tuple(&t, sk, 0, CONN_TYPE_TCP)) {
        increment_telemetry_count(tcp_done_failed_tuple);
        return 0;
    }
    log_debug("kprobe/tcp_done: netns: %u, sport: %u, dport: %u", t.netns, t.sport, t.dport);
    skp_conn_tuple_t skp_conn = {.sk = sk, .tup = t};

    // connection timeouts will have 0 pids as they are cleaned up by an idle process.
    // resets can also have kernel pids are they are triggered by receiving an RST packet from the server
    // get the pid from the ongoing failure map in this case, as it should have been set in connect(). else bail
    pid_ts_t *failed_conn_pid = bpf_map_lookup_elem(&tcp_ongoing_connect_pid, &skp_conn);
    if (failed_conn_pid) {
        bpf_map_delete_elem(&tcp_ongoing_connect_pid, &skp_conn);
        t.pid = GET_USER_MODE_PID(failed_conn_pid->pid_tgid);
    } else {
        increment_telemetry_count(tcp_done_missing_pid);
        return 0;
    }

    if (!handle_tcp_failure(sk, &t)) {
        return 0;
    }

    if (cleanup_conn(ctx, &t, sk) == 0) {
        increment_telemetry_count(tcp_done_connection_flush);
    }

    return 0;
}

SEC("kretprobe/tcp_done")
int BPF_KRETPROBE(kretprobe__tcp_done_flush) {
    flush_conn_close_if_full(ctx);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_close, struct sock *sk) {
    conn_tuple_t t = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Get network namespace id
    log_debug("kprobe/tcp_close: kernel thread id: %llu, user mode pid: %llu", GET_KERNEL_THREAD_ID(pid_tgid), GET_USER_MODE_PID(pid_tgid));
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }
    log_debug("kprobe/tcp_close: netns: %u, sport: %u, dport: %u", t.netns, t.sport, t.dport);

    // If protocol classification is disabled, then we don't have kretprobe__tcp_close_clean_protocols hook
    // so, there is no one to use the map and clean it.
    if (is_protocol_classification_supported()) {
        bpf_map_update_with_telemetry(tcp_close_args, &pid_tgid, &t, BPF_ANY);
    }

    skp_conn_tuple_t skp_conn = {.sk = sk, .tup = t};
    skp_conn.tup.pid = 0;

    bpf_map_delete_elem(&tcp_ongoing_connect_pid, &skp_conn);

    handle_tcp_failure(sk, &t);

    if (cleanup_conn(ctx, &t, sk) == 0) {
        increment_telemetry_count(tcp_close_connection_flush);
    }

    return 0;
}

SEC("kretprobe/tcp_close")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__tcp_close_clean_protocols) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    conn_tuple_t *tup_ptr = (conn_tuple_t *)bpf_map_lookup_elem(&tcp_close_args, &pid_tgid);
    if (tup_ptr) {
        clean_protocol_classification(tup_ptr);
        bpf_map_delete_elem(&tcp_close_args, &pid_tgid);
    }

    if (is_batching_enabled()) {
        bpf_tail_call_compat(ctx, &tcp_close_progs, 0);
    }

    return 0;
}

SEC("kretprobe/tcp_close")
int BPF_KRETPROBE(kretprobe__tcp_close_flush) {
    flush_conn_close_if_full(ctx);
    return 0;
}

#ifdef COMPILE_PREBUILT

SEC("kprobe/tcp_retransmit_skb")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_retransmit_skb, struct sock *sk) {
    int segs = (int)PT_REGS_PARM3(ctx);
    log_debug("kprobe/tcp_retransmit: segs: %d", segs);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    tcp_retransmit_skb_args_t args = {};
    args.sk = sk;
    args.segs = segs;
    bpf_map_update_with_telemetry(pending_tcp_retransmit_skb, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_retransmit_skb_pre_4_7_0, struct sock *sk) {
    log_debug("kprobe/tcp_retransmit");
    u64 pid_tgid = bpf_get_current_pid_tgid();
    tcp_retransmit_skb_args_t args = {};
    args.sk = sk;
    args.segs = 1;
    bpf_map_update_with_telemetry(pending_tcp_retransmit_skb, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_retransmit_skb")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__tcp_retransmit_skb, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (ret < 0) {
        bpf_map_delete_elem(&pending_tcp_retransmit_skb, &pid_tgid);
        return 0;
    }
    tcp_retransmit_skb_args_t *args = bpf_map_lookup_elem(&pending_tcp_retransmit_skb, &pid_tgid);
    if (args == NULL) {
        return 0;
    }
    struct sock *sk = args->sk;
    int segs = args->segs;
    bpf_map_delete_elem(&pending_tcp_retransmit_skb, &pid_tgid);
    log_debug("kretprobe/tcp_retransmit: segs: %d", segs);
    return handle_retransmit(sk, segs);
}

#endif // COMPILE_PREBUILT

#if defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)

SEC("kprobe/tcp_retransmit_skb")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_retransmit_skb, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    tcp_retransmit_skb_args_t args = {};
    args.sk = sk;
    args.segs = 0;
    BPF_CORE_READ_INTO(&args.retrans_out_pre, tcp_sk(sk), retrans_out);
    bpf_map_update_with_telemetry(pending_tcp_retransmit_skb, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_retransmit_skb")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__tcp_retransmit_skb, int rc) {
    log_debug("kretprobe/tcp_retransmit");
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (rc < 0) {
        bpf_map_delete_elem(&pending_tcp_retransmit_skb, &pid_tgid);
        return 0;
    }
    tcp_retransmit_skb_args_t *args = bpf_map_lookup_elem(&pending_tcp_retransmit_skb, &pid_tgid);
    if (args == NULL) {
        return 0;
    }
    struct sock *sk = args->sk;
    u32 retrans_out_pre = args->retrans_out_pre;
    bpf_map_delete_elem(&pending_tcp_retransmit_skb, &pid_tgid);
    u32 retrans_out = 0;
    BPF_CORE_READ_INTO(&retrans_out, tcp_sk(sk), retrans_out);
    return handle_retransmit(sk, retrans_out - retrans_out_pre);
}

// These kprobes fire from kernel timer/softirq context. The shared helpers
// in stats.h handle the map lookup and atomic increment.
SEC("kprobe/tcp_enter_loss")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_enter_loss, struct sock *sk) {
    handle_tcp_enter_loss(sk);
    return 0;
}

SEC("kprobe/tcp_enter_recovery")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_enter_recovery, struct sock *sk) {
    handle_tcp_enter_recovery(sk);
    return 0;
}

SEC("kprobe/tcp_send_probe0")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_send_probe0, struct sock *sk) {
    handle_tcp_send_probe0(sk);
    return 0;
}

#endif // COMPILE_CORE || COMPILE_RUNTIME

SEC("kprobe/tcp_connect")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_connect, struct sock *skp) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("kprobe/tcp_connect: kernel thread id: %llu, user mode pid: %llu", GET_KERNEL_THREAD_ID(pid_tgid), GET_USER_MODE_PID(pid_tgid));

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, skp, 0, CONN_TYPE_TCP)) {
        increment_telemetry_count(tcp_connect_failed_tuple);
        return 0;
    }

    skp_conn_tuple_t skp_conn = {.sk = skp, .tup = t};
    pid_ts_t pid_ts = {.pid_tgid = pid_tgid, .timestamp = bpf_ktime_get_ns()};
    bpf_map_update_with_telemetry(tcp_ongoing_connect_pid, &skp_conn, &pid_ts, BPF_ANY);

    return 0;
}

SEC("kprobe/tcp_finish_connect")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_finish_connect, struct sock *skp) {
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, skp, 0, CONN_TYPE_TCP)) {
        increment_telemetry_count(tcp_finish_connect_failed_tuple);
        return 0;
    }
    skp_conn_tuple_t skp_conn = {.sk = skp, .tup = t};
    pid_ts_t *pid_tgid_p = bpf_map_lookup_elem(&tcp_ongoing_connect_pid, &skp_conn);
    if (!pid_tgid_p) {
        return 0;
    }

    u64 pid_tgid = pid_tgid_p->pid_tgid;
    t.pid = GET_USER_MODE_PID(pid_tgid);
    log_debug("kprobe/tcp_finish_connect: kernel thread id: %llu, user mode pid: %llu", GET_KERNEL_THREAD_ID(pid_tgid), GET_USER_MODE_PID(pid_tgid));

    handle_tcp_stats(&t, skp, TCP_ESTABLISHED);
    handle_message(&t, 0, 0, CONN_DIRECTION_OUTGOING, 0, 0, PACKET_COUNT_NONE, skp);

    log_debug("kprobe/tcp_finish_connect: netns: %u, sport: %u, dport: %u", t.netns, t.sport, t.dport);

    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__inet_csk_accept, struct sock *sk) {
    if (!sk) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("kretprobe/inet_csk_accept: kernel thread id: %llu, user mode pid: %llu", GET_KERNEL_THREAD_ID(pid_tgid), GET_USER_MODE_PID(pid_tgid));

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }
    log_debug("kretprobe/inet_csk_accept: netns: %u, sport: %u, dport: %u", t.netns, t.sport, t.dport);

    handle_tcp_stats(&t, sk, TCP_ESTABLISHED);
    handle_message(&t, 0, 0, CONN_DIRECTION_INCOMING, 0, 0, PACKET_COUNT_NONE, sk);

    port_binding_t pb = {};
    pb.netns = t.netns;
    pb.port = t.sport;
    add_port_bind(&pb, port_bindings);

    skp_conn_tuple_t skp_conn = {.sk = sk, .tup = t};
    skp_conn.tup.pid = 0;
    pid_ts_t pid_ts = {.pid_tgid = pid_tgid, .timestamp = bpf_ktime_get_ns()};
    bpf_map_update_with_telemetry(tcp_ongoing_connect_pid, &skp_conn, &pid_ts, BPF_ANY);

    return 0;
}

SEC("kprobe/inet_csk_listen_stop")
int BPF_BYPASSABLE_KPROBE(kprobe__inet_csk_listen_stop, struct sock *skp) {
    __u16 lport = read_sport(skp);
    if (lport == 0) {
        log_debug("ERR(inet_csk_listen_stop): lport is 0 ");
        return 0;
    }

    port_binding_t pb = { .netns = 0, .port = 0 };
    pb.netns = get_netns_from_sock(skp);
    pb.port = lport;
    remove_port_bind(&pb, &port_bindings);

    log_debug("kprobe/inet_csk_listen_stop: net ns: %u, lport: %u", pb.netns, pb.port);
    return 0;
}

// Represents the parameters being passed to the tracepoint net/net_dev_queue
struct net_dev_queue_ctx {
    u64 unused;
    struct sk_buff *skb;
};

static __always_inline struct sock *sk_buff_sk(struct sk_buff *skb) {
    struct sock *sk = NULL;
#ifdef COMPILE_PREBUILT
    bpf_probe_read(&sk, sizeof(struct sock *), (char *)skb + offset_sk_buff_sock());
#elif defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
    BPF_CORE_READ_INTO(&sk, skb, sk);
#endif

    return sk;
}

static __always_inline int handle_net_dev_queue(struct sk_buff* skb) {
    struct sock *sk = sk_buff_sk(skb);
    if (!sk) {
        return 0;
    }

    conn_tuple_t skb_tup;
    bpf_memset(&skb_tup, 0, sizeof(conn_tuple_t));
    if (sk_buff_to_tuple(skb, &skb_tup) <= 0) {
        return 0;
    }

    if (!(skb_tup.metadata & CONN_TYPE_TCP)) {
        return 0;
    }

    conn_tuple_t sock_tup;
    bpf_memset(&sock_tup, 0, sizeof(conn_tuple_t));
    if (!read_conn_tuple(&sock_tup, sk, 0, CONN_TYPE_TCP)) {
        return 0;
    }
    sock_tup.netns = 0;
    sock_tup.pid = 0;

    if (!is_equal(&skb_tup, &sock_tup)) {
        normalize_tuple(&skb_tup);
        normalize_tuple(&sock_tup);
        // We skip EEXIST because of the use of BPF_NOEXIST flag. Emitting telemetry for EEXIST here spams metrics
        // and do not provide any useful signal since the key is expected to be present sometimes.
        bpf_map_update_with_telemetry(conn_tuple_to_socket_skb_conn_tuple, &sock_tup, &skb_tup, BPF_NOEXIST, -EEXIST);
    }

    return 0;
}

SEC("raw_tracepoint/net/net_dev_queue")
int BPF_PROG(raw_tracepoint__net__net_dev_queue, struct sk_buff *skb) {
    CHECK_BPF_PROGRAM_BYPASSED()
    if (!skb) {
        return 0;
    }

    return handle_net_dev_queue(skb);
}

SEC("tracepoint/net/net_dev_queue")
int tracepoint__net__net_dev_queue(struct net_dev_queue_ctx* ctx) {
    CHECK_BPF_PROGRAM_BYPASSED()
    struct sk_buff* skb = ctx->skb;
    if (!skb) {
        return 0;
    }

    return handle_net_dev_queue(skb);
}

// Kprobe fallback for kernels < 4.15 that don't support multiple tracepoint attachments
//
// Background:
// - On kernel >= 4.17: We use raw_tracepoint/net/net_dev_queue (most efficient)
// - On kernel >= 4.15 but < 4.17: We use tracepoint/net/net_dev_queue
// - On kernel < 4.15: Multiple tracepoint attachments fail with "file exists" error
//                      So we use a kprobe on the underlying kernel function instead
//
// The net/net_dev_queue tracepoint is triggered by dev_queue_xmit_nit() kernel function,
// which is called during packet transmission to notify monitoring tools.
// This allows us to correlate sk_buff data with socket information for protocol classification.

// kprobe on dev_queue_xmit_nit - kernel function that triggers net_dev_queue tracepoint
// Kernel function signature: void dev_queue_xmit_nit(struct sk_buff *skb, struct net_device *dev)
// This replaces:
// - raw_tracepoint/net/net_dev_queue
// - tracepoint/net/net_dev_queue
SEC("kprobe/dev_queue_xmit_nit")
int BPF_BYPASSABLE_KPROBE(kprobe__dev_queue_xmit_nit, struct sk_buff *skb) {
    if (!skb) {
        return 0;
    }

    return handle_net_dev_queue(skb);
}

#endif
