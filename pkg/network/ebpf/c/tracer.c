#include "ktypes.h"
#ifndef COMPILE_CORE
#include "kconfig.h"
#endif
#include "bpf_metadata.h"

#include "tracer/tcp_recv.h"
#include "tracer/tcp_send.h"
#include "tracer/tcp.h"
#include "tracer/udp_recv.h"
#include "tracer/udp_send.h"
#include "tracer/udp.h"
#include "tracer/udpv6.h"
#include "tracer/classifier.h"
#include "tracer/inet.h"
#include "protocols/tls/tls-certs.h"

char _license[] SEC("license") = "GPL";
