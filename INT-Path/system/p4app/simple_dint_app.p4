#include <core.p4>
#include "v1model.p4"

#include "simple_dint_header.p4"
#include "dint_parser.p4"

#define COUNTER_SIZE 32w16

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    counter(COUNTER_SIZE,CounterType.packets) egress_counter;

    @name("_drop")
    action _drop() {
        mark_to_drop(standard_metadata);
    }

	// For Leaf-Spine topology, k=3 -> at most 6 ports in each switch
	register<bit<8>>(16) eport_register;
	register<bit<8>>(16) iport_register;
	register<bit<8>>(1) deviceno_register;
	register<bit<32>>(1) timedelta_register;
	// 1 MB space: 8-bit rsvd, 8-bit egress port, 8-bit deviceno, 8-bit iport (sketch simplification), 32-bit timedelta
	//register<bit<64>>(256) dint_register;

	/*@name("dint_hash")
	action dint_hash() {
		meta.dint_metadata.index = (bit<32>)standard_metadata.egress_port;
	}
	@name("dint_hash_tbl")
	table dint_hash_tbl {
		actions = {
			dint_hash;
		}
		key = {}
		size = 1024;
		default_action = dint_hash();
	}*/

	@name("read_register")
	action read_register() {
		//dint_register.read(meta.dint_metadata.register_value, meta.dint_metadata.index);
		eport_register.read(meta.dint_metadata.prev_eport, (bit<32>)standard_metadata.egress_port);
		iport_register.read(meta.dint_metadata.prev_iport, (bit<32>)standard_metadata.ingress_port);
		deviceno_register.read(meta.dint_metadata.prev_deviceno, 0);
		timedelta_register.read(meta.dint_metadata.prev_timedelta, 0);
	}
	@name("read_register_tbl")
	table read_register_tbl {
		actions = {
			read_register;
		}
		key = {}
		size = 1024;
		default_action = read_register();
	}

	/*@name("parse_register")
	action parse_register() {
		meta.dint_metadata.prev_eport = (bit<8>)(meta.dint_metadata.register_value >> 48);
		meta.dint_metadata.prev_deviceno = (bit<8>)(meta.dint_metadata.register_value >> 40);
		meta.dint_metadata.prev_iport = (bit<8>)(meta.dint_metadata.register_value >> 32);
		meta.dint_metadata.prev_timedelta = (bit<32>)(meta.dint_metadata.register_value);
	}
	@name("parse_register_tbl")
	table parse_register_tbl {
		actions = {
			parse_register;
		}
		key = {}
		size = 1024;
		default_action = parse_register();
	}*/

	@name("delta_calc")
	action delta_calc() {
		hdr.intbitmap.setValid();
		if (meta.dint_metadata.prev_deviceno == meta.int_metadata.device_no) {
			hdr.intbitmap.device_bit = 0;
			meta.dint_metadata.output_deviceno = meta.dint_metadata.prev_deviceno;
		}
		else {
			hdr.intbitmap.device_bit = 1;
			meta.dint_metadata.output_deviceno = meta.int_metadata.device_no;
		}
		if (meta.dint_metadata.prev_iport == (bit<8>)(standard_metadata.ingress_port)) {
			hdr.intbitmap.iport_bit = 0;
			meta.dint_metadata.output_iport = meta.dint_metadata.prev_iport;
		}
		else {
			hdr.intbitmap.iport_bit = 1;
			meta.dint_metadata.output_iport = (bit<8>)(standard_metadata.ingress_port);
		}
		if (meta.dint_metadata.prev_eport == (bit<8>)(standard_metadata.egress_port)) {
			hdr.intbitmap.eport_bit = 0;
			meta.dint_metadata.output_eport = meta.dint_metadata.prev_eport;
		}
		else {
			hdr.intbitmap.eport_bit = 1;
			meta.dint_metadata.output_eport = (bit<8>)(standard_metadata.egress_port);
		}
		if ((meta.dint_metadata.prev_timedelta >= standard_metadata.deq_timedelta) && ((meta.dint_metadata.prev_timedelta - standard_metadata.deq_timedelta) <= 100) || \
				(meta.dint_metadata.prev_timedelta < standard_metadata.deq_timedelta) && ((standard_metadata.deq_timedelta - meta.dint_metadata.prev_timedelta) <= 100)) {
			hdr.intbitmap.timedelta_bit = 0;
			meta.dint_metadata.output_timedelta = meta.dint_metadata.prev_timedelta;
		}
		else {
			hdr.intbitmap.timedelta_bit = 1;
			meta.dint_metadata.output_timedelta = standard_metadata.deq_timedelta;
		}
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.udp.hdrChecksum = 16w0;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	@name("delta_calc_tbl")
	table delta_calc_tbl {
		actions = {
			delta_calc;
		}
		key = {}
		size = 1024;
		default_action = delta_calc();
	}

	/*action set_bitmap() {
		hdr.intbitmap.setValid();
		hdr.intbitmap.device_bit = 1;
		meta.dint_metadata.output_deviceno = meta.int_metadata.device_no;
		hdr.intbitmap.iport_bit = 1;
		meta.dint_metadata.output_iport = (bit<8>)(standard_metadata.ingress_port);
		hdr.intbitmap.eport_bit = 1;
		meta.dint_metadata.output_eport = (bit<8>)(standard_metadata.egress_port);
		hdr.intbitmap.timedelta_bit = 1;
		meta.dint_metadata.output_timedelta = standard_metadata.deq_timedelta;
	}
	table set_bitmap_tbl {
		actions = {
			set_bitmap;
		}
		key = {}
		size = 1024;
		default_action = set_bitmap();
	}*/

	action do_deviceno() {
		hdr.intdeviceno.setValid();
		hdr.intdeviceno.device_no = meta.int_metadata.device_no;
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	table do_deviceno_tbl {
		actions = {
			do_deviceno;
		}
		key = {}
		size = 1024;
		default_action = do_deviceno();
	}

	action donot_deviceno() {
		hdr.intdeviceno.setInvalid();
	}
	table donot_deviceno_tbl {
		actions = {
			donot_deviceno;
		}
		key = {}
		size = 1024;
		default_action = donot_deviceno();
	}

	action do_iport() {
		hdr.intiport.setValid();
		hdr.intiport.ingress_port = (bit<8>)(standard_metadata.ingress_port);
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	table do_iport_tbl {
		actions = {
			do_iport;
		}
		key = {}
		size = 1024;
		default_action = do_iport();
	}

	action donot_iport() {
		hdr.intiport.setInvalid();
	}
	table donot_iport_tbl {
		actions = {
			donot_iport;
		}
		key = {}
		size = 1024;
		default_action = donot_iport();
	}

	action do_eport() {
		hdr.inteport.setValid();
		hdr.inteport.egress_port = (bit<8>)(standard_metadata.egress_port);
		hdr.udp.len = hdr.udp.len+16w1;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w1;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w1;
	}
	table do_eport_tbl {
		actions = {
			do_eport;
		}
		key = {}
		size = 1024;
		default_action = do_eport();
	}

	action donot_eport() {
		hdr.inteport.setInvalid();
	}
	table donot_eport_tbl {
		actions = {
			donot_eport;
		}
		key = {}
		size = 1024;
		default_action = donot_eport();
	}

	action do_timedelta() {
		hdr.inttimedelta.setValid();
		hdr.inttimedelta.timedelta = standard_metadata.deq_timedelta;
		hdr.udp.len = hdr.udp.len+16w4;
		hdr.ipv4.totalLen  = hdr.ipv4.totalLen+16w4;
		hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum-16w4;
	}
	table do_timedelta_tbl {
		actions = {
			do_timedelta;
		}
		key = {}
		size = 1024;
		default_action = do_timedelta();
	}
	
	action donot_timedelta() {
		hdr.inttimedelta.setInvalid();
	}
	table donot_timedelta_tbl {
		actions = {
			donot_timedelta;
		}
		key = {}
		size = 1024;
		default_action = donot_timedelta();
	}

	action update_register() {
		/*dint_register.write(meta.dint_metadata.index, \
				((bit<64>)(meta.dint_metadata.output_eport)<<48) | \
				((bit<64>)(meta.dint_metadata.output_deviceno)<<40) | \
				((bit<64>)(meta.dint_metadata.output_iport)<<32) | \
				(bit<64>)(meta.dint_metadata.output_timedelta));*/
		eport_register.write((bit<32>)standard_metadata.egress_port, meta.dint_metadata.output_eport);
		iport_register.write((bit<32>)standard_metadata.ingress_port, meta.dint_metadata.output_iport);
		deviceno_register.write(0, meta.dint_metadata.output_deviceno);
		timedelta_register.write(0, meta.dint_metadata.output_timedelta);
	}
	table update_register_tbl {
		actions = {
			update_register;
		}
		key = {}
		size = 1024;
		default_action = update_register();
	}

	action set_timedelta(bit<32> timedelta) {
		standard_metadata.deq_timedelta = timedelta;
	}
	table set_timedelta_tbl {
		actions = {
			set_timedelta;	
		}
		key = {
			standard_metadata.egress_port:exact;
		}
		size = 1024;
	}

	action remove_softhard_diff() {
		standard_metadata.deq_timedelta = standard_metadata.deq_timedelta>>7; // /100
	}
	table remove_softhard_diff_tbl {
		actions = {
			remove_softhard_diff;
		}
		key = {}
		size = 1024;
		default_action = remove_softhard_diff();
	}
	
    apply {
		set_timedelta_tbl.apply();
		remove_softhard_diff_tbl.apply();
        egress_counter.count((bit<32>)standard_metadata.egress_port);
        if (hdr.sr.isValid()) {
			//dint_hash_tbl.apply();
			read_register_tbl.apply();
			//parse_register_tbl.apply();
			/*if ((bit<8>)(standard_metadata.egress_port) == meta.dint_metadata.prev_eport) {
				// If egress port matches, keep loaded prev metadata
				// Delta calculation (set bitmap according to delta)
				delta_calc_tbl.apply();
			}
			else {
				// Set bitmap as <1, 1, 1>
				set_bitmap_tbl.apply();
			}*/
			delta_calc_tbl.apply();
			if (hdr.intbitmap.device_bit == 1) {
				do_deviceno_tbl.apply();
			}
			else {
				donot_deviceno_tbl.apply();
			}
			if (hdr.intbitmap.iport_bit == 1) {
				do_iport_tbl.apply();
			}
			else {
				donot_iport_tbl.apply();
			}
			if (hdr.intbitmap.eport_bit == 1 ) {
				do_eport_tbl.apply();
			}
			else {
				donot_eport_tbl.apply();
			}
			if (hdr.intbitmap.timedelta_bit == 1) {
				do_timedelta_tbl.apply();
			}
			else {
				donot_timedelta_tbl.apply();
			}
			update_register_tbl.apply();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    counter(COUNTER_SIZE,CounterType.packets) ingress_counter;

    @name("_drop")
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name("l2setmetadata")
    action l2setmetadata(bit<9> port) {
        standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
    }
    @name("l2setmetadataecmp")
    action l2setmetadataecmp(bit<2> routeNum, bit<16> portData) {
        bit<32> result=32w0;
        random(result,32w0,(bit<32>)(routeNum-2w1));
        bit<16> data=portData;
        if (result == 32w1) {
            data=portData>>4;
        }else if(result == 32w2){
            data=portData>>8;
        }else if(result==32w3){
            data=portData>>4;
            data=portData>>8;
        }
        bit<9> port=(bit<9>)((bit<4>)data);
        standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
    }
    @name("arpreply")
    action arpreply(bit<48>repmac) {
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        standard_metadata.egress_port = standard_metadata.ingress_port;
        hdr.ethernet.srcAddr=repmac;
        hdr.ethernet.dstAddr=hdr.arp.arpSha;
        bit<32> tempip;
        tempip=hdr.arp.arpSpa;
        hdr.arp.arpSpa=hdr.arp.arpTpa;
        hdr.arp.arpTpa=tempip;
        hdr.arp.arpTha=hdr.arp.arpSha;
        hdr.arp.arpSha=repmac;
    }
    @name("srrouting")
    action srrouting() {
        // read 8 bit from routingList use listPosition
        // and set it to egress metadata
        bit<8> port=(bit<8>)hdr.sr.routingList;
        hdr.sr.routingList=hdr.sr.routingList>>8;
        standard_metadata.egress_spec = (bit<9>)port+9w1; // 0 -> eth1
        standard_metadata.egress_port = (bit<9>)port+9w1;
    }
    @name("setdeviceno")
    action setdeviceno(bit<8> device_no) {
        meta.int_metadata.device_no=device_no;
    }

    @name("dotrans")
    table dotrans {
        actions = {
            l2setmetadataecmp;
            NoAction;
        }
        key = {
            hdr.ethernet.srcAddr:exact;
            hdr.ethernet.dstAddr:exact;
        }
        size=512;
        default_action=NoAction();
    }
    @name("dosocket")
    table dosocket {
        actions = {
            l2setmetadata;
            NoAction;
        }
        key = {
            hdr.udp.dstPort:exact;
        }
        size=512;
        default_action=NoAction();
    }
    @name("doarp")
    table doarp {
        actions = {
            arpreply;
            NoAction;
        }
        key = {
            //hdr.arp.arpTha:exact;
            hdr.arp.arpTpa:exact;
        }
        size=512;
        default_action=NoAction();
    }
    @name("dosr")
    table dosr {
        actions = {
            srrouting;
        }
        key={}
        size=512;
        default_action=srrouting();
    }
    @name("setmetadata")
    table setmetadata {
        actions = {
            setdeviceno;
            NoAction;
        }
        key={}
        size=512;
        default_action=NoAction();
    }
    apply { 
        setmetadata.apply();
        if (hdr.ipv4.isValid()) {
            if(hdr.sr.isValid()) {
                dosr.apply();
            }else{
                dotrans.apply();
                dosocket.apply();
            }
        } else if(hdr.arp.isValid()) {
            doarp.apply();
        }
        ingress_counter.count((bit<32>)standard_metadata.ingress_port);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
