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

from originalint.p4_pd_rpc.ttypes import *
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

# Change parser.p4 accordingly if changed
IP_DIFFSERV_INT = 0x66

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
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, ["originalint"])

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
            matchspec0 = originalint_ipv4_lpm_match_spec_t(\
                    ipv4_dstAddr = ipv4Addr_to_i32(receiver_ip),
                    ipv4_dstAddr_prefix_length = 32)
            actnspec0 = originalint_ipv4_forward_action_spec_t(self.receiver_devport)
            self.client.ipv4_lpm_table_add_with_ipv4_forward(\
                    self.sess_hdl, self.dev_tgt, matchspec0, actnspec0)

            # Stage 1

            # Table: int_set_header_0_tbl (size: 1)
            #print "Configuring int_set_header_0_tbl"
            #deviceid = 1
            #actnspec0 = originalint_int_set_header_0_action_spec_t(deviceid)
            #self.client.int_set_header_0_tbl_set_default_action_int_set_header_0(\
            #        self.sess_hdl, self.dev_tgt, actnspec0)

            # Egress pipeline

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
