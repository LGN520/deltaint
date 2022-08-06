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

#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/pktgen_headers.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/wred_blackbox.p4>

#include "includes/headers.p4"
#include "includes/parser.p4"

#include "ingress.p4"
#include "egress.p4"

//#define DEBUG

action nop() {
}

control ingress {
	// Stage 0
	if (ipv4.diffserv == IP_DIFFSERV_INT) {
		apply(ipv4_lpm); // set egress port and ttl // set eport
	}

	// Stage 1
	if (ipv4.diffserv == IP_DIFFSERV_INT) {
		//apply(int_set_header_0_tbl); // set switchid
		//apply(int_set_header_1_tbl); // set iport
		apply(int_set_intl45_head_header_tbl);
	}
}

control egress {
	// Stage 0
	if (ipv4.diffserv == IP_DIFFSERV_INT) {
		apply(int_set_header_2_tbl); // set hop latency
	}
}
