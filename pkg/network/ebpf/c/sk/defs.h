#ifndef _SK_DEFS_H_
#define _SK_DEFS_H_

#include "tracer/tracer.h"

#ifndef TCP_ECN_OK
#define TCP_ECN_OK	1
#endif

typedef struct {
    __u64 initial_sent_bytes;
    __u64 initial_recv_bytes;
    __u32 initial_sent_packets;
    __u32 initial_recv_packets;
    __u32 initial_retransmits;

    __u32 pid;
    __u16 state_transitions;
    __u16 failure_reason;
//    __u32 cookie;

    tcp_event_stats_t tcp_event_stats;

    time_ms_t start_ms;
    __u8 direction;
    conn_tuple_t tup;
} sk_tcp_stats_t;

typedef struct {
    __u64 sent_bytes;
    __u64 recv_bytes;
    __u32 sent_packets;
    __u32 recv_packets;
    __u32 pid;
//    __u32 cookie;
    time_ms_t start_ms;
    time_ms_t timestamp_ms;
    __u8 direction;
    conn_tuple_t tup;
} sk_udp_stats_t;

#endif
