typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define XDP_DROP 1
#define XDP_PASS 2
#define ETH_P_IP 0x0800

static inline __u16 bpf_htons(__u16 x) { return __builtin_bswap16(x); }

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct ethhdr {
	__u8  h_dest[6];
	__u8  h_source[6];
	__u16 h_proto;
} __attribute__((packed));

struct iphdr {
	__u8  ihl:4, version:4;
	__u8  tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8  ttl;
	__u8  protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u32);
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	__u32 src_ip = iph->saddr;
	if (bpf_map_lookup_elem(&blocked_ips, &src_ip))
		return XDP_DROP;

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
