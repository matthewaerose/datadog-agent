#ifndef __CLASSIFIER_H
#define __CLASSIFIER_H

#include "bpf_helpers.h"

#include "protocols/classification/protocol-classification.h"

SEC("socket/classifier_entry")
int socket__classifier_entry(struct __sk_buff *skb) {
    protocol_classifier_entrypoint(skb);
    return 0;
}

SEC("socket/classifier_tls_handshake_client")
int socket__classifier_tls_handshake_client(struct __sk_buff *skb) {
    protocol_classifier_entrypoint_tls_handshake_client(skb);
    return 0;
}

SEC("socket/classifier_tls_handshake_server")
int socket__classifier_tls_handshake_server(struct __sk_buff *skb) {
    protocol_classifier_entrypoint_tls_handshake_server(skb);
    return 0;
}

SEC("socket/classifier_queues")
int socket__classifier_queues(struct __sk_buff *skb) {
    protocol_classifier_entrypoint_queues(skb);
    return 0;
}

SEC("socket/classifier_dbs")
int socket__classifier_dbs(struct __sk_buff *skb) {
    protocol_classifier_entrypoint_dbs(skb);
    return 0;
}

SEC("socket/classifier_grpc")
int socket__classifier_grpc(struct __sk_buff *skb) {
    protocol_classifier_entrypoint_grpc(skb);
    return 0;
}

#endif
