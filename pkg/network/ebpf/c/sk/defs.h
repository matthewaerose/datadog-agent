#ifndef _SK_DEFS_H_
#define _SK_DEFS_H_

#include "tracer/tracer.h"

#ifndef TCP_ECN_OK
#define TCP_ECN_OK	1
#endif

typedef struct {
    conn_tuple_t tup;

    __u64 initial_sent_bytes;
    __u64 initial_recv_bytes;
    __u32 initial_sent_packets;
    __u32 initial_recv_packets;
    __u32 initial_retransmits;
    __u16 state_transitions;
    __u16 failure_reason;

    tcp_event_stats_t tcp_event_stats;
    time_ms_t start_ms;
    __u8 direction;
} sk_tcp_stats_t;

typedef struct {
    conn_tuple_t tup;

    __u64 sent_bytes;
    __u64 recv_bytes;
    __u32 sent_packets;
    __u32 recv_packets;
    __u8 flags;
    __u8 direction;
    time_ms_t timestamp_ms;
    time_ms_t start_ms;
} sk_udp_stats_t;

#endif
