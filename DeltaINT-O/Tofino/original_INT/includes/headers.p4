/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2019 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16 (saturating);
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16 (saturating);
        checksum : 16;
    }
}

header_type intl45_head_header_t {
    fields {
        int_type    :8;
        len         :16;
        rsvd1       :8;
    }
}

// INT headers
/*header_type int_header_t {
    fields {
        ver                     : 4;
        rep                     : 2;
        c                       : 1;
        e                       : 1;
        d                       : 1;
        rsvd1                   : 2;
        ins_cnt                 : 5;
        max_hop_cnt             : 8;
        total_hop_cnt           : 8;
        instruction_bitmap_0003 : 4;   // split the bits for lookup
        instruction_bitmap_0407 : 4;
        instruction_bitmap_0811 : 4;
        instruction_bitmap_1215 : 4;
        rsvd2_digest            : 16;
    }
}*/

/*header_type int_switch_id_header_t {
	fields {
		switch_id: 8;
	}
}

header_type int_ingress_port_id_header_t {
	fields {
		ingress_port_id: 8;
	}
}

header_type int_egress_port_id_header_t {
	fields {
		egress_port_id: 8;
	}
}*/

header_type int_hop_latency_header_t {
	fields {
		hop_latency: 8 (signed);
	}
}
