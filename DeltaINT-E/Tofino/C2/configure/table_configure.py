# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# TODO: Replace PROC, ACTION, and TABLE

"""
Thrift PD interface DV test
"""

import logging
import os
import pd_base_tests
import pltfm_pm_rpc
import pal_rpc
import random
import sys
import time
import unittest

from deltaintec2.p4_pd_rpc.ttypes import *
from pltfm_pm_rpc.ttypes import *
from mirror_pd_rpc.ttypes import *
from pal_rpc.ttypes import *
from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
from res_pd_rpc.ttypes import *
from conn_mgr_pd_rpc.ttypes import *
from mc_pd_rpc.ttypes import *
from devport_mgr_pd_rpc.ttypes import *
from ptf_port import *

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(this_dir))

sender_fpport = "11/0"
receiver_fpport = "13/0"
receiver_ip = "10.0.1.13"

# Change main.p4 accordingly if changed
DINT_DSTPORT = 1234
THRESHOLD = 1

huffman_codemap = {0: 0b0, -1: 0b10, 1: 0b11}

srcip_dstip_predicate_list = [1, 2, 4, 8]
srcport_dstport_predicate_list = [1, 2, 4, 8]
protocol_predicate_list = [1, 2]
deviceid_iport_predicate_list = [1, 2, 4, 8]
eport_predicate_list = [1, 2]
ismatch_list = [0, 1]

if test_param_get("arch") == "tofino":
  MIR_SESS_COUNT = 1024
  MAX_SID_NORM = 1015
  MAX_SID_COAL = 1023
  BASE_SID_NORM = 1
  BASE_SID_COAL = 1016
  EXP_LEN1 = 127
  EXP_LEN2 = 63
elif test_param_get("arch") == "tofino2":
  MIR_SESS_COUNT = 256
  MAX_SID_NORM = 255
  MAX_SID_COAL = 255
  BASE_SID_NORM = 0
  BASE_SID_COAL = 0
  EXP_LEN1 = 127
  EXP_LEN2 = 59
else:
  assert False, "Unsupported arch %s" % test_param_get("arch")

class TableConfigure(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        # initialize the thrift data plane
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, ["deltaintec2"])

    def setUp(self):
        print '\nSetup'

        # initialize the connection
        pd_base_tests.ThriftInterfaceDataPlane.setUp(self)
        self.sess_hdl = self.conn_mgr.client_init()
        self.dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        self.platform_type = "mavericks"
        board_type = self.pltfm_pm.pltfm_pm_board_type_get()
        if re.search("0x0234|0x1234|0x4234|0x5234", hex(board_type)):
            self.platform_type = "mavericks"
        elif re.search("0x2234|0x3234", hex(board_type)):
            self.platform_type = "montara"

        # get the device ports from front panel ports
        port, chnl = sender_fpport.split("/")
        devport = self.pal.pal_port_front_panel_port_to_dev_port_get(0, int(port), int(chnl))
        self.sender_devport = devport
        port, chnl = receiver_fpport.split("/")
        devport = self.pal.pal_port_front_panel_port_to_dev_port_get(0, int(port), int(chnl))
        self.receiver_devport = devport

    ### MAIN ###

    def runTest(self):
        if test_param_get('cleanup') != True:
            print '\nTest'

            #####################
            ### Prepare ports ###
            #####################

            # Add and enable the platform ports
            self.pal.pal_port_add(0, self.sender_devport,
                                 pal_port_speed_t.BF_SPEED_40G,
                                 pal_fec_type_t.BF_FEC_TYP_NONE)
            self.pal.pal_port_enable(0, self.sender_devport)
            self.pal.pal_port_add(0, self.receiver_devport,
                                 pal_port_speed_t.BF_SPEED_40G,
                                 pal_fec_type_t.BF_FEC_TYP_NONE)
            self.pal.pal_port_enable(0, self.receiver_devport)

            ################################
            ### Normal MAT Configuration ###
            ################################

            # Ingress pipeline

            # Stage 0

            # Table: ipv4_lpm (default: nop; size: 1)
            print "Configuring ipv4_lpm"
            matchspec0 = deltaintec2_ipv4_lpm_match_spec_t(\
                    udp_hdr_dstPort = DINT_DSTPORT,
                    ipv4_hdr_dstAddr = ipv4Addr_to_i32(receiver_ip),
                    ipv4_hdr_dstAddr_prefix_length = 32)
            actnspec0 = deltaintec2_ipv4_forward_action_spec_t(self.receiver_devport)
            self.client.ipv4_lpm_table_add_with_ipv4_forward(\
                    self.sess_hdl, self.dev_tgt, matchspec0, actnspec0)

            # Egress pipeline

            # Stage 0

            # Table: set_egmeta_tbl (default: nop; size: 1)
            print "Configuring set_egmeta_tbl"
            matchspec0 = deltaintec2_set_egmeta_tbl_match_spec_t(\
                    udp_hdr_dstPort = DINT_DSTPORT)
            self.client.set_egmeta_tbl_table_add_with_set_egmeta(\
                    self.sess_hdl, self.dev_tgt, matchspec0)

            # Table: update_srcip_dstip_tbl (default: nop; size: 1)
            print "Configuring update_srcip_dstip_tbl"
            matchspec0 = deltaintec2_update_srcip_dstip_tbl_match_spec_t(\
                    udp_hdr_dstPort = DINT_DSTPORT)
            self.client.update_srcip_dstip_tbl_table_add_with_update_srcip_dstip(\
                    self.sess_hdl, self.dev_tgt, matchspec0)

            # Table: update_srcport_dstport_tbl (default: nop; size: 1)
            print "Configuring update_srcport_dstport_tbl"
            matchspec0 = deltaintec2_update_srcport_dstport_tbl_match_spec_t(\
                    udp_hdr_dstPort = DINT_DSTPORT)
            self.client.update_srcport_dstport_tbl_table_add_with_update_srcport_dstport(\
                    self.sess_hdl, self.dev_tgt, matchspec0)

            # Table: update_protocol_tbl (default: nop; size: 1)
            print "Configuring update_protocol_tbl"
            matchspec0 = deltaintec2_update_protocol_tbl_match_spec_t(\
                    udp_hdr_dstPort = DINT_DSTPORT)
            self.client.update_protocol_tbl_table_add_with_update_protocol(\
                    self.sess_hdl, self.dev_tgt, matchspec0)

            # Stage 1

            # Table: update_previnput_tbl (default: nop; size: 32)
            print "Configuring update_previnput_tbl"
            for tmp_srcip_dstip_predicate in srcip_dstip_predicate_list:
                for tmp_srcport_dstport_predicate in srcport_dstport_predicate_list:
                    for tmp_protocol_predicate in protocol_predicate_list:
                        matchspec0 = deltaintec2_update_previnput_tbl_match_spec_t(\
                                udp_hdr_dstPort = DINT_DSTPORT,
                                meta_int_srcip_dstip_predicate = tmp_srcip_dstip_predicate,
                                meta_int_srcport_dstport_predicate = tmp_srcport_dstport_predicate,
                                meta_int_protocol_predicate = tmp_protocol_predicate)
                        if tmp_srcip_dstip_predicate == 8 and tmp_srcport_dstport_predicate == 8 and tmp_protocol_predicate == 2:
                            self.client.update_previnput_tbl_table_add_with_update_previnput_matched(\
                                    self.sess_hdl, self.dev_tgt, matchspec0)
                        else:
                            self.client.update_previnput_tbl_table_add_with_update_previnput_unmatched(\
                                    self.sess_hdl, self.dev_tgt, matchspec0)

            # Table ismatch_tbl (default: notmatch; size: 1)
            matchspec0 = deltaintec2_ismatch_tbl_match_spec_t(\
                    meta_int_srcip_dstip_predicate = 8,
                    meta_int_srcport_dstport_predicate = 8,
                    meta_int_protocol_predicate = 2)
            self.client.ismatch_tbl_table_add_with_ismatch(\
                    self.sess_hdl, self.dev_tgt, matchspec0)

            # Stage 2

            # Table set_output_tbl (default: nop; size: 1)
            matchspec0 = deltaintec2_set_output_tbl_match_spec_t(\
                    udp_hdr_dstPort = DINT_DSTPORT)
            self.client.set_output_tbl_table_add_with_set_output(\
                    self.sess_hdl, self.dev_tgt, matchspec0)

            # Stage 3

            # Table: update_prevoutput_tbl (default: nop; size: 2)
            print "Configuring update_prevoutput_tbl"
            for tmp_ismatch in ismatch_list:
                matchspec0 = deltaintec2_update_prevoutput_tbl_match_spec_t(\
                        udp_hdr_dstPort = DINT_DSTPORT,
                        meta_ismatch = tmp_ismatch)
                if tmp_ismatch == 1:
                    self.client.update_prevoutput_tbl_table_add_with_update_prevoutput_matched(\
                            self.sess_hdl, self.dev_tgt, matchspec0)
                else:
                    self.client.update_prevoutput_tbl_table_add_with_update_prevoutput_unmatched(\
                            self.sess_hdl, self.dev_tgt, matchspec0)

            # Stage 4

            # Table: power_insert_tbl (default: insert_latency; size: 3)
            print "Configuring power_insert_tbl"
            for tmp_delta in range(-1 * THRESHOLD, THRESHOLD + 1):
                matchspec0 = deltaintec2_power_insert_tbl_match_spec_t(\
                        meta_ismatch = 1,
                        meta_power_delta = tmp_delta)
                actnspec0 = deltaintec2_insert_power_delta_action_spec_t(huffman_codemap[tmp_delta])
                self.client.power_insert_tbl_table_add_with_insert_power_delta(\
                        self.sess_hdl, self.dev_tgt, matchspec0, actnspec0)

            self.conn_mgr.complete_operations(self.sess_hdl)
            self.conn_mgr.client_cleanup(self.sess_hdl) # close session

    def cleanup_table(self, table, iscalled=False):
        if iscalled:
            table = 'self.client.' + table
            # get entry count
            num_entries = eval(table + '_get_entry_count')\
                          (self.sess_hdl, self.dev_tgt)
            print "Number of entries : {}".format(num_entries)
            if num_entries == 0:
                return
            # get the entry handles
            hdl = eval(table + '_get_first_entry_handle')\
                    (self.sess_hdl, self.dev_tgt)
            if num_entries > 1:
                hdls = eval(table + '_get_next_entry_handles')\
                    (self.sess_hdl, self.dev_tgt, hdl, num_entries - 1)
                hdls.insert(0, hdl)
            else:
                hdls = [hdl]
            # delete the table entries
            for hdl in hdls:
                entry = eval(table + '_get_entry')\
                    (self.sess_hdl, self.dev_tgt.dev_id, hdl, True)
                eval(table + '_table_delete_by_match_spec')\
                    (self.sess_hdl, self.dev_tgt, entry.match_spec)
