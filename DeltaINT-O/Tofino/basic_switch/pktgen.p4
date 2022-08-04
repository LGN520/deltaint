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

/*
 * pktgen processing
 */

control process_pktgen {
#ifdef PKTGEN_ENABLE
    if (valid(pktgen_generic)) {
#ifdef BFD_OFFLOAD_ENABLE
        if (bfd_meta.pkt_tx != 0) {
            /* process bfd tx packets (from pktgen) */
            process_bfd_tx_packet();
        }
#endif /* BFD_OFFLOAD_ENABLE */
    } else if (valid(pktgen_port_down)) {
        /* process port down event */
        process_pktgen_port_down();
    } else if (valid(pktgen_recirc)) {
        /* process recirculation event */
        process_pktgen_nhop_down();
    }
#endif /* PKTGEN_ENABLE */
}
