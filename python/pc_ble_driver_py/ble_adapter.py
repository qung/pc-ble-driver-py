#
# Copyright (c) 2016 Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
#   3. Neither the name of Nordic Semiconductor ASA nor the names of other
#   contributors to this software may be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
#   4. This software must only be used in or with a processor manufactured by Nordic
#   Semiconductor ASA, or in or with a processor manufactured by a third party that
#   is used in combination with a processor manufactured by Nordic Semiconductor.
#
#   5. Any software provided in binary or object form under this license must not be
#   reverse engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
try:
    import queue
except ImportError:
    import Queue as queue
import logging
from threading  import Condition, Lock
from ble_driver import *

logger  = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class DbConnection(object):
    def __init__(self):
        self.services    = list()
        self.serv_disc_q = queue.Queue()
        self.char_disc_q = queue.Queue()
        self.desc_disc_q = queue.Queue()


    def get_char_value_handle(self, uuid):
        if isinstance(uuid, BLEUUID):
            uuid = uuid.value

        for s in self.services:
            for c in s.chars:
                if c.uuid.value == uuid:
                    for d in c.descs:
                        if d.uuid.value == uuid:
                            return d.handle
        return None


    def get_cccd_handle(self, uuid):
        if isinstance(uuid, BLEUUID):
            uuid = uuid.value

        for s in self.services:
            for c in s.chars:
                if c.uuid.value == uuid:
                    for d in c.descs:
                        if d.uuid.value == BLEUUID.Standard.cccd:
                            return d.handle
                    break
        return None


    def get_char_handle(self, uuid):
        if isinstance(uuid, BLEUUID):
            uuid = uuid.value

        for s in self.services:
            for c in s.chars:
                if c.uuid.value == uuid:
                    return c.handle_decl
        return None


    def get_char_uuid(self, handle):
        for s in self.services:
            for c in s.chars:
                if (c.handle_decl <= handle) and (c.end_handle >= handle):
                    return c.uuid


class EvtSync(object):
    def __init__(self):
        self.conds                                = dict()
        self.conds[BLEEvtID.gattc_evt_write_rsp]  = Condition(Lock())
        self.conds[BLEEvtID.evt_tx_complete]      = Condition(Lock())


    def wait(self, evt):
        with self.conds[evt]:
            self.conds[evt].wait()


    def notify(self, evt):
        with self.conds[evt]:
            self.conds[evt].notify_all()



class BLEAdapterObserver(object):
    def __init__(self, *args, **kwargs):
        super(BLEAdapterObserver, self).__init__()


    def on_notification(self, ble_adapter, conn_handle, uuid, data):
        pass



class BLEAdapter(BLEDriverObserver):
    observer_lock   = Lock()
    def __init__(self, ble_driver):
        super(BLEAdapter, self).__init__()
        self.driver             = ble_driver
        self.driver.observer_register(self)

        self.conn_in_progress   = False
        self.observers          = list()
        self.db_conns           = dict()
        self.evt_sync           = dict()


    def connect(self, address, scan_params=None, conn_params=None):
        if self.conn_in_progress:
            return
        self.driver.ble_gap_connect(address     = address,
                                    scan_params = scan_params,
                                    conn_params = conn_params)
        self.conn_in_progress = True


    @synchronized(observer_lock)
    def observer_register(self, observer):
        self.observers.append(observer)


    @synchronized(observer_lock)
    def observer_unregister(self, observer):
        self.observers.remove(observer)


    def service_discovery(self, conn_handle, uuid=None):
        self.driver.ble_gattc_prim_srvc_disc(conn_handle, uuid, 0x0001)

        while True:
            services = self.db_conns[conn_handle].serv_disc_q.get(timeout=5)
            if services:
                self.db_conns[conn_handle].services.extend(services)
            else:
                break

            if services[-1].end_handle == 0xFFFF:
                break
            else:
                self.driver.ble_gattc_prim_srvc_disc(conn_handle,
                                                     uuid,
                                                     services[-1].end_handle + 1)

        for s in self.db_conns[conn_handle].services:
            self.driver.ble_gattc_char_disc(conn_handle, s.start_handle, s.end_handle)
            while True:
                chars = self.db_conns[conn_handle].char_disc_q.get(timeout=5)
                if chars:
                    list(map(s.char_add, chars))
                else:
                    break

                self.driver.ble_gattc_char_disc(conn_handle, chars[-1].handle_decl + 1, s.end_handle)

            for ch in s.chars:
                self.driver.ble_gattc_desc_disc(conn_handle, ch.handle_value, ch.end_handle)
                while True:
                    descs = self.db_conns[conn_handle].desc_disc_q.get(timeout=5)
                    if descs:
                        ch.descs.extend(descs)
                    else:
                        break

                    if descs[-1].handle == ch.end_handle:
                        break
                    else:
                        self.driver.ble_gattc_desc_disc(conn_handle,
                                                        descs[-1].handle + 1,
                                                        ch.end_handle)


    def enable_notification(self, conn_handle, uuid):
        cccd_list = [1, 0]

        handle = self.db_conns[conn_handle].get_cccd_handle(uuid)
        if handle == None:
            raise NordicSemiException('CCCD not found')

        write_params = BLEGattcWriteParams(BLEGattWriteOperation.write_req,
                                           BLEGattExecWriteFlag.prepared_cancel,
                                           handle,
                                           cccd_list,
                                           0)

        self.driver.ble_gattc_write(conn_handle, write_params)
        self.evt_sync[conn_handle].wait(evt = BLEEvtID.gattc_evt_write_rsp)


    def write_req(self, conn_handle, uuid, data):
        handle = self.db_conns[conn_handle].get_char_value_handle(uuid)
        if handle == None:
            raise NordicSemiException('Characteristic value handler not found')
        write_params = BLEGattcWriteParams(BLEGattWriteOperation.write_req,
                                           BLEGattExecWriteFlag.prepared_cancel,
                                           handle,
                                           data,
                                           0)
        self.driver.ble_gattc_write(conn_handle, write_params)
        self.evt_sync[conn_handle].wait(evt = BLEEvtID.gattc_evt_write_rsp)


    def write_cmd(self, conn_handle, uuid, data):
        handle = self.db_conns[conn_handle].get_char_value_handle(uuid)
        if handle == None:
            raise NordicSemiException('Characteristic value handler not found')
        write_params = BLEGattcWriteParams(BLEGattWriteOperation.write_cmd,
                                           BLEGattExecWriteFlag.prepared_cancel,
                                           handle,
                                           data,
                                           0)
        self.driver.ble_gattc_write(conn_handle, write_params)
        self.evt_sync[conn_handle].wait(evt = BLEEvtID.evt_tx_complete)


    def on_gap_evt_connected(self, ble_driver, conn_handle, peer_addr, own_addr, role, conn_params):
        self.db_conns[conn_handle]  = DbConnection()
        self.evt_sync[conn_handle]  = EvtSync()
        self.conn_in_progress       = False


    def on_gap_evt_timeout(self, ble_driver, conn_handle, src):
        if src == BLEGapTimeoutSrc.conn:
            self.conn_in_progress = False


    def on_evt_tx_complete(self, ble_driver, conn_handle, count):
        self.evt_sync[conn_handle].wait(evt = BLEEvtID.evt_tx_complete)


    def on_gattc_evt_write_rsp(self, ble_driver, conn_handle, status, error_handle, attr_handle, write_op, offset, data):
        self.evt_sync[conn_handle].notify(evt = BLEEvtID.gattc_evt_write_rsp)


    def on_gattc_evt_prim_srvc_disc_rsp(self, ble_driver, conn_handle, status, services):
        if status == BLEGattStatusCode.attribute_not_found:
            self.db_conns[conn_handle].serv_disc_q.put(None)
            return

        elif status != BLEGattStatusCode.success:
            logger.error("Error. Primary services discovery failed. Status {}.".format(status))
            return
        self.db_conns[conn_handle].serv_disc_q.put(services)


    def on_gattc_evt_char_disc_rsp(self, ble_driver, conn_handle, status, characteristics):
        if status == BLEGattStatusCode.attribute_not_found:
            self.db_conns[conn_handle].char_disc_q.put(None)
            return

        elif status != BLEGattStatusCode.success:
            logger.error("Error. Characteristic discovery failed. Status {}.".format(status))
            return
        self.db_conns[conn_handle].char_disc_q.put(characteristics)


    def on_gattc_evt_desc_disc_rsp(self, ble_driver, conn_handle, status, descriptions):
        if status == BLEGattStatusCode.attribute_not_found:
            self.db_conns[conn_handle].desc_disc_q.put(None)
            return

        elif status != BLEGattStatusCode.success:
            logger.error("Error. Descriptor discovery failed. Status {}.".format(status))
            return
        self.db_conns[conn_handle].desc_disc_q.put(descriptions)


    @synchronized(observer_lock)
    def on_gattc_evt_hvx(self, ble_driver, conn_handle, status, error_handle, attr_handle, hvx_type, data):
        if status != BLEGattStatusCode.success:
            logger.error("Error. Handle value notification failed. Status {}.".format(status))
            return

        if hvx_type == BLEGattHVXType.notification:
            uuid = self.db_conns[conn_handle].get_char_uuid(attr_handle)
            if uuid == None:
                raise NordicSemiException('UUID not found')

            for obs in self.observers:
                obs.on_notification(ble_adapter = self,
                                    conn_handle = conn_handle, 
                                    uuid        = uuid,
                                    data        = data)
