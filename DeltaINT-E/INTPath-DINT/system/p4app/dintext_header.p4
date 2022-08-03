#ifndef __HEADER_H__
#define __HEADER_H__ 1

struct ingress_metadata_t {
    bit<32> nhop_ipv4;
}

@metadata
struct intrinsic_metadata_t {
    bit<48> ingress_global_timestamp;
    bit<32> lf_field_list;
    bit<16> mcast_grp;
    bit<16> egress_rid;
    bit<8>  resubmit_flag;
    bit<8>  recirculate_flag;
}

@metadata @name("queueing_metadata")
struct queueing_metadata_t {
    bit<48> enq_timestamp;
    bit<16> enq_qdepth;
    bit<32> deq_timedelta;
    bit<16> deq_qdepth;
}

@metadata @name("int_metadata")
struct int_metadata_t {
    bit<8> device_no;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> arpHdr;     /* format of hardware address */
    bit<16> arpPro;     /* format of protocol address */
    bit<8>  arpHln;     /* length of hardware address */
    bit<8>  arpPln;     /* length of protocol address */
    bit<16> arpOp;      /* ARP/RARP operation */
    bit<48> arpSha;     /* sender hardware address */
    bit<32> arpSpa;     /* sender protocol address */
    bit<48> arpTha;     /* target hardware address */
    bit<32> arpTpa;     /* target protocol address */
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;       //udp 17, tcp 6
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> hdrChecksum;
}

header sr_t {               //source routing header
    bit<512> routingList; 
}

header intbitmap_t {
	bit<1> device_bit;
	bit<1> iport_bit;
	bit<1> eport_bit;
	bit<1> timedelta_bit;
	bit<4> rsvd;
}

header intdeviceno_t {
	bit<8> device_no;
}

header intiport_t {
	bit<8> ingress_port;
}

header inteport_t {
	bit<8> egress_port;
}

header inttimedelta_t {
	bit<32> timedelta;
}

header inttimedelta_delta_t {
	bit<8> timedelta_delta;
}

struct dint_metadata_t {
	bit<32> index;
	bit<128> register_value;
	//bit<32> register_value;
	bit<32> srcAddr;
	bit<32> dstAddr;
	bit<16> srcPort;
	bit<16> dstPort;
	bit<8> protocol;
	bit<8> prev_deviceno;
	bit<8> prev_iport;
	bit<8> prev_eport;
	bit<32> prev_timedelta;
	bit<8> output_deviceno;
	bit<8> output_iport;
	bit<8> output_eport;
	bit<32> output_timedelta;
}

struct metadata {
    @name("ingress_metadata")
    ingress_metadata_t   ingress_metadata;
    @name("intrinsic_metadata")
    intrinsic_metadata_t intrinsic_metadata;
    @name("queueing_metadata")
    queueing_metadata_t queueing_metadata;
    @name("int_metadata")
    int_metadata_t int_metadata;
	@name("dint_metadata")
	dint_metadata_t dint_metadata;
}

struct headers {
    @name("ethernet")
    ethernet_t  ethernet;
    @name("arp")
    arp_t       arp;
    @name("ipv4")
    ipv4_t      ipv4;
    @name("udp")
    udp_t       udp;
    @name("sr")
    sr_t        sr;
	@name("intbitmap")
	intbitmap_t intbitmap;
    @name("intdeviceno")
	intdeviceno_t intdeviceno;
	@name("intiport")
	intiport_t intiport;
	@name("inteport")
	inteport_t inteport;
	@name("inttimedelta")
	inttimedelta_t inttimedelta;
	@name("inttimedelta_delta")
	inttimedelta_delta_t inttimedelta_delta;
}

#endif // __HEADER_H__
