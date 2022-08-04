
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
 * other reason codes shared between P4 program and APIs 
 * Must match the definitions in switch_hostif.h file
 */

#define CPU_REASON_CODE_DEFAULT          0x0
#define CPU_REASON_CODE_SFLOW            0x4
#define CPU_REASON_CODE_PTP              0x8
#define CPU_REASON_CODE_MYIP             0x400
#define CPU_REASON_CODE_GLEAN            0x213
