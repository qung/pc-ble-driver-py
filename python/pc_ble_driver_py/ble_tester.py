#!/usr/bin/python
# -*- coding: ascii -*-

"""
:abstract:      BLE tester module.
:author:        Hussar Test Team.
:copyright:     Nordic Semiconductor ASA.
"""

import threading
import queue as Queue
from pynrfjprog import API

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from pc_ble_driver_py import config
config.__conn_ic_id__ = "NRF52"
from pc_ble_driver_py.ble_adapter import *
from pc_ble_driver_py.ble_driver import *

nrf_sd_ble_api_ver = config.sd_api_ver_get()

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

gap_status = {0x00: "BLE_GAP_SEC_STATUS_SUCCESS",
              0x01: "BLE_GAP_SEC_STATUS_TIMEOUT",
              0x02: "BLE_GAP_SEC_STATUS_PDU_INVALID",
              0x03: "BLE_GAP_SEC_STATUS_RFU_RANGE1_BEGIN",
              0x80: "BLE_GAP_SEC_STATUS_RFU_RANGE1_END",
              0x81: "BLE_GAP_SEC_STATUS_PASSKEY_ENTRY_FAILED",
              0x82: "BLE_GAP_SEC_STATUS_OOB_NOT_AVAILABLE",
              0x83: "BLE_GAP_SEC_STATUS_AUTH_REQ",
              0x84: "BLE_GAP_SEC_STATUS_CONFIRM_VALUE",
              0x85: "BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP",
              0x86: "BLE_GAP_SEC_STATUS_ENC_KEY_SIZE",
              0x87: "BLE_GAP_SEC_STATUS_SMP_CMD_UNSUPPORTED",
              0x88: "BLE_GAP_SEC_STATUS_UNSPECIFIED",
              0x89: "BLE_GAP_SEC_STATUS_REPEATED_ATTEMPTS",
              0x8A: "BLE_GAP_SEC_STATUS_INVALID_PARAMS",
              0x8B: "BLE_GAP_SEC_STATUS_RFU_RANGE2_BEGIN",
              0xFF: "BLE_GAP_SEC_STATUS_RFU_RANGE2_END"}


class BLELocalCharacteristic(object):
    def __init__(self, value_handle, user_desc_handle, cccd_handle, sccd_handle):
        log.info('New local charcteristic: value_handle: {}, cccd_handle: {}'.format(value_handle, cccd_handle))
        self.value_handle     = value_handle
        self.user_desc_handle = user_desc_handle
        self.cccd_handle      = cccd_handle
        self.sccd_handle      = sccd_handle

    @classmethod
    def from_c(cls, gatts_service):
        return cls(value_handle     = gatts_service.value_handle,
                   user_desc_handle = gatts_service.user_desc_handle,
                   cccd_handle      = gatts_service.cccd_handle,
                   sccd_handle      = gatts_service.sccd_handle)


def change_endianness(input_string):
    output = ""
    for i in range(len(input_string) - 1, 0, -2):
        output += input_string[i - 1]
        output += input_string[i]
    return output


class PublicKey(object):

    def __init__(self, x, y, curve_type):
        # in python3 no longer long, all are int
        # assert isinstance(x, (int, long)), 'Invalid argument type'
        # assert isinstance(y, (int, long)), 'Invalid argument type'
        assert isinstance(x, int), 'Invalid argument type'
        assert isinstance(y, int), 'Invalid argument type'
        self.x = x
        self.y = y
        self.curve_type = curve_type

    def to_c(self):

        log.debug("ECDH key: Before: x: {:X}".format(self.x))
        log.debug("ECDH key: Before: y: {:X}".format(self.y))

        x_list = self._int_to_list(self.x)[::-1]
        y_list = self._int_to_list(self.y)[::-1]

        log.debug("ECDH key: After: x: {}".format(" ".join(["0x{:02X}".format(i) for i in x_list])))
        log.debug("ECDH key: After: y: {}".format(" ".join(["0x{:02X}".format(i) for i in y_list])))

        return util.list_to_uint8_array(x_list + y_list)

    def _int_to_list(self, input_integer):
        output_list = []
        input_hex_string = "{:X}".format(input_integer)

        # Add zeros to start key if they are stripped.
        while len(input_hex_string) < 64:
            input_hex_string = "0" + input_hex_string

        for i in range(1, len(input_hex_string), 2):
            output_list.append(int((input_hex_string[i-1] + input_hex_string[i]), 16))

        return output_list



class KeySet(object):

    def __init__(self, keyset):
        self.id_key_own = driver.ble_gap_id_key_t()
        self.id_key_peer = driver.ble_gap_id_key_t()

        self.enc_key_own = driver.ble_gap_enc_key_t()
        self.enc_key_peer = driver.ble_gap_enc_key_t()

        self.sign_info_own = driver.ble_gap_sign_info_t()
        self.sign_info_peer = driver.ble_gap_sign_info_t()

        self.lesc_pk_own = driver.ble_gap_lesc_p256_pk_t()
        self.lesc_pk_peer = driver.ble_gap_lesc_p256_pk_t()

        self.id_key_own.id_info.irk = keyset.keys_own.p_id_key.id_info.irk
        self.id_key_own.id_addr_info.addr_id_peer = keyset.keys_own.p_id_key.id_addr_info.addr_id_peer
        self.id_key_own.id_addr_info.addr_type = keyset.keys_own.p_id_key.id_addr_info.addr_type
        self.id_key_own.id_addr_info.addr = keyset.keys_own.p_id_key.id_addr_info.addr
        self.id_key_peer.id_info.irk = keyset.keys_peer.p_id_key.id_info.irk
        self.id_key_peer.id_addr_info.addr_id_peer = keyset.keys_peer.p_id_key.id_addr_info.addr_id_peer
        self.id_key_peer.id_addr_info.addr_type = keyset.keys_peer.p_id_key.id_addr_info.addr_type
        self.id_key_peer.id_addr_info.addr = keyset.keys_peer.p_id_key.id_addr_info.addr

        self.enc_key_own.enc_info.ltk = keyset.keys_own.p_enc_key.enc_info.ltk
        self.enc_key_own.enc_info.lesc = keyset.keys_own.p_enc_key.enc_info.lesc
        self.enc_key_own.enc_info.auth = keyset.keys_own.p_enc_key.enc_info.auth
        self.enc_key_own.enc_info.ltk_len = keyset.keys_own.p_enc_key.enc_info.ltk_len
        self.enc_key_own.master_id.ediv = keyset.keys_own.p_enc_key.master_id.ediv
        self.enc_key_own.master_id.rand = keyset.keys_own.p_enc_key.master_id.rand
        self.enc_key_peer.enc_info.ltk = keyset.keys_peer.p_enc_key.enc_info.ltk
        self.enc_key_peer.enc_info.lesc = keyset.keys_peer.p_enc_key.enc_info.lesc
        self.enc_key_peer.enc_info.auth = keyset.keys_peer.p_enc_key.enc_info.auth
        self.enc_key_peer.enc_info.ltk_len = keyset.keys_peer.p_enc_key.enc_info.ltk_len
        self.enc_key_peer.master_id.ediv = keyset.keys_peer.p_enc_key.master_id.ediv
        self.enc_key_peer.master_id.rand = keyset.keys_peer.p_enc_key.master_id.rand

        self.sign_info_own.csrk = keyset.keys_own.p_sign_key.csrk
        self.sign_info_peer.csrk = keyset.keys_peer.p_sign_key.csrk

        self.lesc_pk_own.pk = keyset.keys_own.p_pk.pk
        self.lesc_pk_peer.pk = keyset.keys_peer.p_pk.pk


class BleTester(BLEDriverObserver, BLEAdapterObserver):
    """ SDK team BLE tester Class.

    Wraps the pc-ble-driver-py with configuration and methods
    needed to verify SDK drivers, modules and examples.

    """

    def __init__(self, serial_port='COM23', baud_rate=115200, segger_id=681570478):
        super(BleTester, self).__init__()

        self.serial_port = serial_port
        self.baud_rate = baud_rate
        self.segger_id = segger_id

        self.evt_log         = []
        self.conn_targets    = []
        self.stored_keyset   = []
        self.stored_services = []
        self.advertisements  = {}
        self.min_rssi        = None

        self.evt_q              = None
        self.evt_sync           = None
        self.adapter            = None
        self.ble_driver         = None

        self.irk                = None
        self.role               = None
        self.keyset             = None
        self.peer_addr          = None
        self.sec_params         = None
        self.adv_params         = None
        self.conn_handle        = None
        self.conn_params        = None
        self.scan_params        = None
        self.sec_params_backup  = None
        self.lesc_dhkey         = None
        self.lesc_private_key   = None
        self.lesc_own_public_key= None

        self.lesc_enabled           = False
        self.own_ltk_corrupted      = False
        self.peer_ltk_corrupted     = False
        self.conn_failed            = False
        self.conn_in_progress       = False
        self.connect_by_BLE_address = False
        self.last_connected_addr    = ""
        self.lock = threading.RLock()

        self.gatt_char_props = dict(
            broadcast=0,
            read=1,
            write_wo_resp=0,
            write=1,
            notify=1,
            indicate=0,
            auth_signed_write=0
        )

        self.sd_ble_api_ver = config.sd_api_ver_get()

        # Setup keys and configurations
        self.setup_adv_params()
        self.setup_sec_params()
        self.setup_conn_params()
        self.clear_keyset()
        self.setup_scan_params()
        self.open()

    # --------------------------------------------------------------
    # - Control and log methods.
    # --------------------------------------------------------------

    def open(self):
        """ Open BLE tester.

        """
        self.ble_driver = SdkBLEDriver(serial_port=self.serial_port,
                                       baud_rate=self.baud_rate,
                                       auto_flash=False)

        self.adapter = SdkBLEAdapter(self.ble_driver)
        self.adapter.observer_register(self)
        self.adapter.driver.observer_register(self)

        self.evt_q = Queue.Queue()

        self.reset_tester_board()
        self.enable_adapter()

    def close(self):
        """ Close BLE tester.

        """
        self.adapter.observer_unregister(self)
        self.adapter.driver.observer_unregister(self)
        self.conn_handle = None
        self.evt_sync = None
        self.adapter.driver.close()
        self.adapter.close()

    def stop_ble_tester(self):
        """ Stop the Ble driver.

        """
        self.reset_tester_board()

    def restart_ble_tester(self):
        """ Restart the Ble driver.

        """
        self.adapter.driver.ble_enable(BLEEnableParams(vs_uuid_count=10,
                                                       service_changed=True,
                                                       periph_conn_count=1,
                                                       central_conn_count=1,
                                                       central_sec_count=1))

    def reset_tester_board(self):
        """ Reset Tester board.

        """
        api = API.API(API.DeviceFamily.NRF52)
        api.open()
        api.connect_to_emu_with_snr(self.segger_id)
        api.sys_reset()
        api.go()
        api.close()
        time.sleep(3)

    def wait_for_event(self, evt, timeout=20, expected=True, do_log=True):
        """ Wait for event to appear in event log.

        Args:
            evt:      Event to wait for in event log.
            timeout:  Timeout in seconds.
            expected: Is event expected.
                      Used to verify that event is not in event log.
            do_log:   Log events.

        Returns: True, if expected event appears in event log within timeout seconds.
                 False, if not.

        """

        def timeout_func():
            self.evt_q.put(None)

        t = threading.Timer(timeout, timeout_func)
        t.start()
        while True:
            pulled_evt = self.evt_q.get()
            self.evt_q.task_done()
            self.evt_log.append(pulled_evt)

            if pulled_evt == evt:
                try:
                    t.cancel()
                except Exception:
                    pass
                if expected:
                    if pulled_evt != 'tx_complete':
                        if do_log:
                            log.info("Received expected event {}".format(pulled_evt))
                    return True
                else:
                    if do_log:
                        log.error("Received un-expected event {}.".format(pulled_evt))
                    return False

            if pulled_evt is None:
                if expected:
                    if do_log:
                        log.error("Wait for event timed out, expected event:"
                                  "{}\nEvt log: {}".format(evt, self.evt_log))
                    return False
                else:
                    if do_log:
                        log.info("Event {} not recieved, as expected.".format(evt))
                    return True

    def evt_log_contains(self, evt):
        """ Check if expected event is present in the event log.

        Args:
            evt: Expected evt

        Returns: True if expected event is present in event log,
                 False if missing.

        """
        if evt in self.evt_log:
            return True
        return False

    def clear_evt_log(self):
        """ Clear event log.

        """
        self.evt_log = []

    def log_message_handler(self, severity, log_message):
        unused = severity
        log.error("RPC Message: {}".format(log_message))

    # --------------------------------------------------------------
    # - Configuration/Setup methods.
    # --------------------------------------------------------------

    def enable_adapter(self):
        """ Enable BLE adapter with default parameters.

        """
        self.adapter.open()
        ble_enable_params = BLEEnableParams(vs_uuid_count=10,
                                            service_changed=True,
                                            periph_conn_count=1,
                                            central_conn_count=1,
                                            central_sec_count=1)

        if nrf_sd_ble_api_ver >= 3:
            # log.info("Enabling larger ATT MTUs")
            # ble_enable_params.att_mtu = 50
            pass

        if self.sd_ble_api_ver != 5:
            self.adapter.driver.ble_enable(ble_enable_params)
        else:
            self.adapter.driver.ble_enable()

    def add_vs_uuid(self, uuid_base):
        """ Add a Vendor Specific base UUID.

        Args:
            uuid_base: 16 byte vendor specific UUID as list.

        """
        assert isinstance(uuid_base, BLEUUIDBase), 'Invalid argument type'
        self.ble_driver.ble_vs_uuid_add(uuid_base)
        log.info("Added vendor specific UUID: {}".format(uuid_base.base))

    def setup_conn_params(self):
        """ Setup default connection parameters.

        """
        with self.lock:
            self.conn_params = BLEGapConnParams(min_conn_interval_ms=15,
                                                max_conn_interval_ms=30,
                                                conn_sup_timeout_ms=4000,
                                                slave_latency=0)

    def setup_scan_params(self):
        """ Setup default scan parameters.

        """
        with self.lock:
            self.scan_params = BLEGapScanParams(interval_ms=200,
                                                window_ms=200,
                                                timeout_s=10)

    def setup_sec_params(self):
        """ Setup default security parameters.

        """
        kdist_own = BLEGapSecKDist(enc=True,
                                   id=True,
                                   sign=False,
                                   link=False)

        kdist_peer = BLEGapSecKDist(enc=True,
                                    id=True,
                                    sign=False,
                                    link=False)

        self.sec_params = BLEGapSecParams(bond=True,
                                          mitm=False,
                                          lesc=False,
                                          keypress=False,
                                          io_caps=BLEGapIOCaps.none,
                                          oob=False,
                                          min_key_size=7,
                                          max_key_size=16,
                                          kdist_own=kdist_own,
                                          kdist_peer=kdist_peer)

    def setup_adv_params(self):
        """ Setup default advertisement parameters.

        """
        self.adv_params = BLEGapAdvParams(interval_ms=40,
                                          timeout_s=180)

    def set_whitelist(self):
        """ Set whitelist.

        NOT TESTED.

        """
        irk = driver.ble_gap_irk_t()
        irk_array = util.list_to_uint8_array([1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7])
        irk.irk = irk_array.cast()
        whitelist = driver.ble_gap_whitelist_t()
        pt = ctypes.cast(irk, ctypes.POINTER(self.adapter.driver.ble_gap_irk_t))
        whitelist.pp_irks = pt
        whitelist.irk_count = 1

    def set_irk(self, key):
        """ Set own local Identity Resolving Key.

        Args:
            key: IRK. 16 bytes list

        """
        if len(key) != 16:
            raise Exception("IRK key length must be 16 bytes")
        log.info("Local IRK changed to {}".format(' '.join([hex(x) for x in key])))
        self.irk = key

    def set_ltk(self, ltk):
        """ Update current peer LTK.

        Args:
            ltk: New LTK as list of 16 bytes.

        """
        ltk = util.list_to_uint8_array(ltk)
        self.enc_key_peer.enc_info.ltk = ltk.cast()
        log.info("Updated peer LTK: {}".format(util.uint8_array_to_list(self.enc_key_peer.enc_info.ltk, 16)))

    def set_conn_targets(self, conn_targets):
        """ Set BLE device names to scan for.

        Args:
            conn_targets: List of BLE device names.

        """
        self.conn_targets = conn_targets

    def set_adv_data(self, device_name='Hussar_Test'):
        """ Set local BLE device advertisement name.

        Args:
            device_name: BLE device name as string.

        """
        adv_data = BLEAdvData(complete_local_name=device_name)
        self.ble_driver.ble_gap_adv_data_set(adv_data)
        log.info("Advertising data set, device name: {}".format(device_name))

    def get_ltk(self):
        """ Get current peer LTK.

        Returns: LTK as byte list

        """
        ltk = util.uint8_array_to_list(self.keyset.keys_peer.p_enc_key.enc_info.ltk, 16)
        log.info("Current peer LTK: {}".format(ltk))
        return ltk

    def clear_keyset(self):
        """ Setup keyset structure.

        """
        self.lesc_enabled = False
        self.own_ltk_corrupted = False
        self.peer_ltk_corrupted = False

        self.keyset = driver.ble_gap_sec_keyset_t()

        self.id_key_own = driver.ble_gap_id_key_t()
        self.id_key_peer = driver.ble_gap_id_key_t()

        self.enc_key_own = driver.ble_gap_enc_key_t()
        self.enc_key_peer = driver.ble_gap_enc_key_t()

        self.sign_info_own = driver.ble_gap_sign_info_t()
        self.sign_info_peer = driver.ble_gap_sign_info_t()

        self.lesc_pk_own = driver.ble_gap_lesc_p256_pk_t()
        self.lesc_pk_peer = driver.ble_gap_lesc_p256_pk_t()

        self.keyset.keys_own.p_enc_key   = self.enc_key_own
        self.keyset.keys_own.p_id_key    = self.id_key_own
        self.keyset.keys_own.p_sign_key  = self.sign_info_own
        self.keyset.keys_own.p_pk        = self.lesc_pk_own
        self.keyset.keys_peer.p_enc_key  = self.enc_key_peer
        self.keyset.keys_peer.p_id_key   = self.id_key_peer
        self.keyset.keys_peer.p_sign_key = self.sign_info_peer
        self.keyset.keys_peer.p_pk       = self.lesc_pk_peer

    def restore_keyset(self, keyset):
        """ Restore current key set to a previously stored key set.

        Args:
            index: Key set index to restore.

        """
        self.keyset.keys_own.p_enc_key = keyset.enc_key_own
        self.keyset.keys_own.p_id_key = keyset.id_key_own
        self.keyset.keys_own.p_sign_key = keyset.sign_info_own
        self.keyset.keys_own.p_pk = keyset.lesc_pk_own
        self.keyset.keys_peer.p_enc_key = keyset.enc_key_peer
        self.keyset.keys_peer.p_id_key = keyset.id_key_peer
        self.keyset.keys_peer.p_sign_key = keyset.sign_info_peer
        self.keyset.keys_peer.p_pk = keyset.lesc_pk_peer

        log.debug("Restored peer LTK: {}".format(util.uint8_array_to_list(
            self.keyset.keys_peer.p_enc_key.enc_info.ltk, 16)))
        log.debug("Restored own LTK: {}".format(util.uint8_array_to_list(
            self.keyset.keys_own.p_enc_key.enc_info.ltk, 16)))
        log.debug("Restored Peer ediv {}".format(
            self.keyset.keys_peer.p_enc_key.master_id.ediv))
        log.debug("Restored Own  ediv {}".format(
            self.keyset.keys_own.p_enc_key.master_id.ediv))

    def restore_current_services(self, services):
        """ Restore the current service database to a stored one.

        Args:
            services: The services to restore.

        """
        self.adapter.db_conns[self.conn_handle] = services

    def clear_current_services(self):
        """ Clear the current service database.

        """
        self.adapter.db_conns.clear()

    def get_advertisements(self):
        return self.advertisements

    # --------------------------------------------------------------
    # - BLE Gap methods.
    # --------------------------------------------------------------

    def init_services(self):
        """ Initialize local services.
        Should be overridden in subclass.

        """
        pass

    def set_address(self, gap_addr):
        """ Set the local BLE address.

        The IRK (self.irk) must to be set prior to calling this method.
        Else the default IRK will be used.

        Args:
            gap_addr: Gap address of type BLEGapAddr.


        """
        assert isinstance(gap_addr, (BLEGapAddr)), 'Invalid argument type'

        log.info("Set BLE address to {}".format(gap_addr.addr))

        # Set privacy if using private address
        if gap_addr.addr_type == BLEGapAddr.Types.random_private_resolvable or \
                        gap_addr.addr_type == BLEGapAddr.Types.random_private_non_resolvable:
            ble_privacy_params = BLEGapPrivacyParams(privacy_mode=driver.BLE_GAP_PRIVACY_MODE_DEVICE_PRIVACY,
                                                     private_addr_type=gap_addr.addr_type.value,
                                                     private_addr_cycle_s=0,
                                                     irk=self.irk)
            self.ble_driver.ble_gap_privacy_set(ble_privacy_params)
        else:
            ble_privacy_params = BLEGapPrivacyParams(privacy_mode=driver.BLE_GAP_PRIVACY_MODE_OFF,
                                                     private_addr_type=driver.BLE_GAP_ADDR_TYPE_RANDOM_PRIVATE_RESOLVABLE,
                                                     private_addr_cycle_s=0,
                                                     irk=self.irk)
            self.ble_driver.ble_gap_privacy_set(ble_privacy_params)
            self.ble_driver.ble_gap_addr_set(gap_addr=gap_addr)

    def get_address(self):
        """ Get the local BLE address object.

        Returns: BLEGapAddr object.

        """
        address = driver.ble_gap_addr_t()
        self.ble_driver.ble_gap_addr_get(address)
        return BLEGapAddr.from_c(address)

    def start_adv(self, device_name='Hussar_Test'):
        """ Initialize services and start advertising.

        Args:
            device_name: BLE advertisement name.

        """
        self.init_services()
        self.set_adv_data(device_name)
        self.start_advertising()

    def start_scan(self, min_rssi=None):
        """ Initialize services and start scanning.

        """
        self.min_rssi = min_rssi
        self.advertisements = {}
        self.init_services()
        self.scan_start()

    def scan_start(self):
        """ Start actual scanning.

        """
        self.role = BLEGapRoles.central
        with self.lock:
            self.ble_driver.ble_gap_scan_start(self.scan_params)

    def scan_stop(self):
        """ Stop scanning.

        """
        err_code = None
        while(err_code == None):
            time.sleep(0.1)
            err_code = self.ble_driver.ble_gap_scan_stop()

        if err_code != driver.NRF_SUCCESS:
            log.error("Scan stop failed, error code {}".format(err_code))

    def start_advertising(self):
        """ Initiate advertising.

        """
        self.role = BLEGapRoles.periph
        self.adapter.driver.ble_gap_adv_start(self.adv_params)
        log.info("Advertising started")

    def disconnect(self, conn_handle=None):
        if conn_handle is None:
            conn_handle = self.conn_handle
        self.ble_driver.ble_gap_disconnect(conn_handle=conn_handle)
        log.info("Disconnect command issued for connection handle {:04X}".format(conn_handle))

    def connect_to_last(self):
        """ Connect to last connected device using BLE address.

        """
        with self.lock:
            err_code = self.ble_driver.ble_gap_connect(self.peer_addr,
                                                       self.scan_params,
                                                       self.conn_params)
        if err_code != driver.NRF_SUCCESS:
            raise Exception("Connect request failed, reason {:02X}".format(err_code))

    def check_conn_sec(self, key_size, sm, lv):
        """ Call ble_gap_conn_sec_get to verify current security status.

        Args:
            key_size: Expected key size.
            sm:       Expected Security Mode.
            lv:       Expected Security Level.

        Returns:
            True if all security params are as expected, else False.

        """
        retval = True
        conn_sec = self.ble_driver.ble_gap_conn_sec_get(conn_handle=self.conn_handle)

        if not conn_sec.encr_key_size == key_size:
            log.error("check_conn_sec() - Expected key size {}, got {}".format(key_size, conn_sec.encr_key_size))
            retval = False
        if not conn_sec.sec_mode.sm == sm:
            log.error("check_conn_sec() - Expected sec_mode sm {}, got {}".format(sm, conn_sec.sec_mode.sm))
            retval = False
        if not conn_sec.sec_mode.lv == lv:
            log.error("check_conn_sec() - Expected sec_mode lv {}, got {}".format(lv, conn_sec.sec_mode.lv))
            retval = False

        return retval

    def verify_stable_connection(self):
        """ Verify connection, and verify that
        ConnectionFailedToBeEstablished (0x3e) is not received.

        Returns:
            True if connected, else False.

        """
        if self.role == BLEGapRoles.periph:
            if self.wait_for_event("connected"):
                log.info("Successfully Connected")
                return True
            else:
                log.error("Failure - connect event not received!")
                return False

        elif self.role == BLEGapRoles.central:
            if self.wait_for_event("connected"):
                retries = 5

                while retries:
                    if self.wait_for_event("disconnected", timeout=1, expected=False, do_log=False):
                        break

                    with self.lock:
                        address_string = "".join("{0:02X}".format(byte) for byte in self.peer_addr.addr)
                    log.warning("0x3e, trying to re-connect to: {}".format(address_string))
                    time.sleep(1)

                    with self.lock:
                        self.adapter.connect(address=self.peer_addr,
                                             scan_params=self.scan_params,
                                             conn_params=self.conn_params)
                    retries -= 1
                else:
                    if self.wait_for_event("disconnected", timeout=1):
                        log.error("Failure - Connection failed due to 0x3e")
                        return False

                log.info("Successfully Connected")
                return True

            else:
                log.error("Failure - connect event not received!")
                return False
        else:
            log.error("Error - Unknown device role while connecting.")
            return False

    def encrypt_link(self):
        """ Encrypt the link using stored keys.

        """
        if self.lesc_enabled:
            log.info("encrypt_link is lesc: {}".format(self.keyset.keys_own.p_enc_key.enc_info.lesc))
            log.info("encrypt_link ltk: {}".format(
                util.uint8_array_to_list(self.keyset.keys_own.p_enc_key.enc_info.ltk, 16)))
            log.info("encrypt_link master_id ediv: {}".format(self.keyset.keys_own.p_enc_key.master_id.ediv))
            log.info("encrypt_link master_id rand: {}".format(
                util.uint8_array_to_list(self.keyset.keys_own.p_enc_key.master_id.rand, 8)))
            self.ble_driver.ble_gap_encrypt(self.conn_handle,
                                            self.keyset.keys_own.p_enc_key.master_id,
                                            self.keyset.keys_own.p_enc_key.enc_info)
        else:
            log.info("encrypt_link is lesc {}".format(self.keyset.keys_peer.p_enc_key.enc_info.lesc))
            log.info("encrypt_link ltk {}".format(
                util.uint8_array_to_list(self.keyset.keys_peer.p_enc_key.enc_info.ltk, 16)))
            log.info("encrypt_link master_id ediv {}".format(self.keyset.keys_peer.p_enc_key.master_id.ediv))
            log.info("encrypt_link master_id rand {}".format(
                util.uint8_array_to_list(self.keyset.keys_peer.p_enc_key.master_id.rand, 8)))
            self.ble_driver.ble_gap_encrypt(self.conn_handle,
                                            self.keyset.keys_peer.p_enc_key.master_id,
                                            self.keyset.keys_peer.p_enc_key.enc_info)

    def sec_params_reply(self):
        """ Send a valid sec params reply with stored keys and security params.
        This method should be called in response to a sec_params_request.

        """
        log.info('sending sec_params_reply')
        log.info("p_keyset irk: {}".format(util.uint8_array_to_list(self.keyset.keys_own.p_id_key.id_info.irk, 16)))

        self.ble_driver.ble_gap_sec_params_reply(self.conn_handle,
                                                 BLEGapSecStatus.success,
                                                 self.sec_params,
                                                 self.keyset,
                                                 None)

    def sec_info_reply(self):
        """ Send a vaild sec info reply with stored keys.
        This method should be called in response to a sec_info_request.

        """
        log.info('sending sec_info_reply')
        log.info("LTK: {}".format(util.uint8_array_to_list(self.keyset.keys_own.p_enc_key.enc_info.ltk, 16)))

        self.ble_driver.ble_gap_sec_info_reply(self.conn_handle,
                                               self.keyset.keys_own.p_enc_key.enc_info,
                                               None,
                                               None)

    def initiate_bond(self, func_before_request = lambda: None):
        """ Initiate security procedure for the connected device.
        Will wait for sec_params_req event, and reply with sec_params_reply using
        stored sec_params and key_set.

        """
        log.info("Calling ble_gap_authenticate")
        self.ble_driver.ble_gap_authenticate(self.conn_handle, self.sec_params)
        self.wait_for_event('sec_params_request')

        func_before_request()

        log.info("Calling ble_gap_sec_params_reply")
        if self.role == BLEGapRoles.central:
            self.sec_params_backup = self.sec_params
            self.sec_params = None
        self.sec_params_reply()

    # --------------------------------------------------------------
    # - BLE Gattc methods.
    # --------------------------------------------------------------

    def discover_services(self, uuid=None):
        """ Start service discovery.
        Discovered services will be stored in ble_adapter.

        Args:
            uuid: Specific service UUID to be found.

        """
        self.adapter.service_discovery(conn_handle=self.conn_handle,
                                       uuid=uuid)

    def enable_notification(self, conn_handle, uuid):
        """ Enable notification for given characteristic.

        Args:
            conn_handle: Connection handle of peer device.
            uuid:        Characteristic UUID as BLEUUID object.

        """
        self.adapter.enable_notification(conn_handle, uuid)
        log.info("Notifications enabled on uuid 0x{}".format(uuid))

    def enable_indication(self, conn_handle, uuid):
        """ Enable indication for given characteristic.

        Args:
            conn_handle: Connection handle of peer device.
            uuid:        Characteristic UUID as BLEUUID object.

        """
        self.adapter.enable_notification(conn_handle, uuid, indication=True)
        log.info("Indication enabled on handle 0x{}".format(uuid))

    def disable_notification(self, conn_handle, uuid):
        """ Disable notification for given characteristic.

        Args:
            conn_handle: Connection handle of peer device.
            uuid:        Characteristic UUID as BLEUUID object.

        """
        self.adapter.disable_notification(conn_handle, uuid)
        log.info("Notifications disabled on handle 0x{}".format(uuid))

    def disable_indication(self, conn_handle, uuid):
        """ Disable indication for given characteristic.

        Args:
            conn_handle: Connection handle of peer device.
            uuid:        Characteristic UUID as BLEUUID object.

        """
        self.adapter.disable_notification(conn_handle, uuid)
        log.info("Indication disabled on handle 0x{}".format(uuid))

    def gattc_read(self, conn_handle, uuid):
        """ Read a peer characteristic.
        Will block until data is received.

        Args:
            conn_handle: Connection handle of peer device.
            uuid:        Characteristic UUID as BLEUUID object.

        Returns: Peer characteristic data.

        """
        handle = self.adapter.db_conns[conn_handle].get_char_value_handle(uuid)
        if handle == None:
            raise NordicSemiException('Characteristic value handler not found')
        self.ble_driver.ble_gattc_read(conn_handle, handle, 0)
        result = self.adapter.evt_sync[conn_handle].wait(evt=BLEEvtID.gattc_evt_read_rsp)
        gatt_res = result['status']
        if gatt_res == BLEGattStatusCode.success:
            return (gatt_res, result['data'])
        else:
            return (gatt_res, None)

    def gattc_write(self, conn_handle, data, uuid, write_op=BLEGattWriteOperation.write_req):
        """ Write to a given peer Characteristic.
        Verify the error code in test case if write operation is Write Request.

        Args:
            conn_handle: Connection handle of peer device.
            data:        Data to write to the characteristic.
            uuid:        Characteristic UUID as BLEUUID object.

        """
        handle = self.adapter.db_conns[conn_handle].get_char_value_handle(uuid)
        if handle == None:
            raise NordicSemiException('Characteristic value handler not found')
        write_params = BLEGattcWriteParams(write_op,
                                           BLEGattExecWriteFlag.unused,
                                           handle,
                                           data,
                                           0)
        self.ble_driver.ble_gattc_write(conn_handle, write_params)

        if write_op == BLEGattWriteOperation.write_req:
            pass
        elif write_op == BLEGattWriteOperation.write_cmd:
            if self.sd_ble_api_ver != 5:
                assert self.adapter.evt_sync[conn_handle].wait(evt=BLEEvtID.evt_tx_complete)
            else:
                assert self.adapter.evt_sync[conn_handle].wait(evt=BLEEvtID.gattc_evt_write_cmd_tx_complete)
        else:
            raise Exception("Error: Invalid Write operation: {}".format(write_op))

    # --------------------------------------------------------------
    # - BLE Gatts methods.
    # --------------------------------------------------------------

    def set_default_char_props(self):
        self.gatt_char_props = dict(
            broadcast=0,
            read=1,
            write_wo_resp=0,
            write=1,
            notify=1,
            indicate=0,
            auth_signed_write=0,
        )

    def add_service(self, uuid, primary=True):
        """ Add a new service to the local database.

        Args:
            uuid:    Service uuid as BLEUUID object.
            primary: Primary service or not.

        Returns:
            Handle of the new service.

        """
        handle_send = driver.new_uint16()
        if primary:
            srv_type = driver.BLE_GATTS_SRVC_TYPE_PRIMARY
        else:
            srv_type = driver.BLE_GATTS_SRVC_TYPE_SECONDARY
        self.ble_driver.ble_gatts_service_add(srv_type, uuid, handle_send)
        serv_handle = driver.uint16_value(handle_send)
        driver.delete_uint16(handle_send)

        log.info("Service 0x{:04X} initialized, handle {}".format(uuid.value, serv_handle))
        return serv_handle

    def add_characteristic(self, service_handle, uuid, cccd=True):
        """ Add a new characteristic to a service in the local database.

        Args:
            service_handle: The handle of the parent service.
            uuid:           Characteristic uuid as BLEUUID object.
            cccd:           Should the characteristic have a CCCD.

        Returns:
            Handle of the new characteristic.
        """
        char_md = driver.ble_gatts_char_md_t()
        attr_char_value = driver.ble_gatts_attr_t()
        attr_md = driver.ble_gatts_attr_md_t()
        char_handle = driver.ble_gatts_char_handles_t()

        initial_value = driver.uint8_array(2)
        initial_value[0] = 0x01
        initial_value[1] = 0x02

        char_md.char_props.read = self.gatt_char_props['read']
        char_md.char_props.write = self.gatt_char_props['write']
        char_md.char_props.indicate = self.gatt_char_props['indicate']
        char_md.char_props.auth_signed_write = self.gatt_char_props['auth_signed_write']
        char_md.char_props.write_wo_resp = self.gatt_char_props['write_wo_resp']
        char_md.char_props.broadcast = self.gatt_char_props['broadcast']
        char_md.p_char_user_desc = None
        char_md.p_char_pf = None
        char_md.p_user_desc_md = None
        char_md.p_sccd_md = None

        if cccd:
            cccd_md = driver.ble_gatts_attr_md_t()
            cccd_md.read_perm.sm = 1
            cccd_md.read_perm.lv = 1
            cccd_md.write_perm.sm = 1
            cccd_md.write_perm.lv = 1
            cccd_md.vloc = driver.BLE_GATTS_VLOC_STACK

            char_md.char_props.notify = 1
            char_md.p_cccd_md = cccd_md
        else:
            char_md.char_props.notify = 0
            char_md.p_cccd_md = None

        attr_md.read_perm.sm = 1
        attr_md.read_perm.lv = 1
        attr_md.write_perm.sm = 1
        attr_md.write_perm.lv = 1
        attr_md.vloc = driver.BLE_GATTS_VLOC_STACK
        attr_md.rd_auth = 0
        attr_md.wr_auth = 0
        attr_md.vlen = 1

        attr_char_value.p_uuid = uuid.to_c()
        attr_char_value.p_attr_md = attr_md
        attr_char_value.init_len = 2
        attr_char_value.init_offs = 0
        attr_char_value.max_len = 20
        attr_char_value.p_value = initial_value.cast()

        self.ble_driver.ble_gatts_characteristic_add(service_handle,
                                                     char_md,
                                                     attr_char_value,
                                                     char_handle)
        # log.info("Characteristic 0x{:04X} for service handle {} initialized".format(uuid.value, service_handle))
        return BLELocalCharacteristic.from_c(char_handle)

    def send_notification(self, value_handle, value, length=2):
        """ Send a notification to a connected peer device.

        Args:
            value_handle:  Characteristic Value Handle.
            value:         Notification data content.
            length:        Length of data in bytes.

        """
        byte = 8

        if self.conn_handle == driver.BLE_CONN_HANDLE_INVALID:
            return
        if length > 4:
            log.warning("Failed - Trying to send larger notification than 4 bytes")

        hvx_params = driver.ble_gatts_hvx_params_t()
        _value = driver.uint8_array(length)

        # Put value data into the list _value in little endian format
        for i in xrange(length):
            i_reversed = length - i - 1
            bit_pos = i_reversed * byte
            _value[i] = (value >> bit_pos) & 0xFF

        hvx_length = driver.new_uint16()
        driver.uint16_assign(hvx_length, length)

        hvx_params.handle = value_handle
        hvx_params.type = driver.BLE_GATT_HVX_NOTIFICATION
        hvx_params.offset = 0
        hvx_params.p_len = hvx_length
        hvx_params.p_data = _value.cast()

        self.ble_driver.ble_gatts_hvx(self.conn_handle, hvx_params)

        actual_hvx_length = driver.uint16_value(hvx_length)
        driver.delete_uint16(hvx_length)

        if length != actual_hvx_length:
            error_code = driver.NRF_ERROR_DATA_SIZE
            log.info("Failed to send notification, hvx length. "
                     "Error code: 0x{0:02X}".format(error_code))
            return

    def send_indication(self, value_handle, value, length=2):
        """ Send a indication to a connected peer device.

        Args:
            value_handle:  Characteristic Value Handle.
            value:         Indication data content.
            length:        Length of data in bytes.

        """
        byte = 8

        if self.conn_handle == driver.BLE_CONN_HANDLE_INVALID:
            return
        if length > 4:
            log.warning("Failed - Trying to send larger indication than 4 bytes")

        hvx_params = driver.ble_gatts_hvx_params_t()
        _value = driver.uint8_array(length)

        # Put value data into the list _value in little endian format
        for i in xrange(length):
            i_reversed = length - i - 1
            bit_pos = i_reversed * byte
            _value[i] = (value >> bit_pos) & 0xFF

        hvx_length = driver.new_uint16()
        driver.uint16_assign(hvx_length, length)

        hvx_params.handle = value_handle
        hvx_params.type = driver.BLE_GATT_HVX_INDICATION
        hvx_params.offset = 0
        hvx_params.p_len = hvx_length
        hvx_params.p_data = _value.cast()

        self.ble_driver.ble_gatts_hvx(self.conn_handle, hvx_params)

        actual_hvx_length = driver.uint16_value(hvx_length)
        driver.delete_uint16(hvx_length)

        if length != actual_hvx_length:
            error_code = driver.NRF_ERROR_DATA_SIZE
            log.info("Failed to send indication, hvx lenght. "
                     "Error code: 0x{}".format(error_code))
            return

    # --------------------------------------------------------------
    # - BLE Gap event functions
    # --------------------------------------------------------------
    def on_gap_evt_connected(self, ble_driver, conn_handle, peer_addr, role, conn_params):
        """

        Args:
            ble_driver:  Reference to the calling BLE driver.
            conn_handle: Connection handle of connected device.
            peer_addr:   BLE address of connected device.
            role:        Own BLE role for this connection.
            conn_params:

        Returns:

        """
        with self.lock:
            self.conn_in_progress = False
            self.peer_addr = peer_addr
            self.role = role
            self.conn_handle = conn_handle

        address_string = "".join("{0:02X}".format(byte) for byte in peer_addr.addr)
        log.info("Connected, connection handle 0x{:04X} Address:"
                 " 0x{}, Role: {}".format(conn_handle, address_string, role))
        log.info("LTK {}".format(util.uint8_array_to_list(self.keyset.keys_peer.p_enc_key.enc_info.ltk, 16)))
        self.evt_q.put('connected')

    def on_gap_evt_timeout(self, ble_driver, conn_handle, src):
        log.info("Gap timeout event, conn handle: {}, source: {}".format(conn_handle, src))
        self.evt_q.put('timeout')

    # TODO: Must be added in pc-ble-driver-py
    def on_gap_evt_passkey_display(self, ble_event):
        log.info("Passkey_display event")
        self.evt_q.put('passkey_display')

    def on_gap_evt_conn_param_update_request(self, ble_driver, conn_handle, conn_params):
        log.info("conn_param_update event")
        self.evt_q.put('conn_param_update')

    def on_gap_evt_auth_key_request(self, ble_driver, conn_handle, key_type):
        log.info("Auth key request event")
        self.evt_q.put('auth_key_request')

    def on_gap_lesc_dhkey_request(self, ble_driver, conn_handle, peer_public_key, oobd_req):
        log.info('LESC dhkey request event')

        self.lesc_enabled = True
        self.lesc_pk_peer = peer_public_key

        # Translate incoming peer public key to x an y components as integers.
        peer_public_key_list = util.uint8_array_to_list(self.lesc_pk_peer.pk, 64)
        peer_public_key_x = int(change_endianness("".join(["{:02X}".format(i) for i in peer_public_key_list[:32]])), 16)
        peer_public_key_y = int(change_endianness("".join(["{:02X}".format(i) for i in peer_public_key_list[32:]])), 16)

        log.info("Peer public DH key, big endian, x: 0x{:X}, y: 0x{:X}".format(peer_public_key_x, peer_public_key_y))

        # Generate a _EllipticCurvePublicKey object of the received peer public key.
        lesc_peer_public_key_obj = ec.EllipticCurvePublicNumbers(peer_public_key_x,
                                                                 peer_public_key_y,
                                                                 ec.SECP256R1())
        lesc_peer_public_key_obj2 = lesc_peer_public_key_obj.public_key(default_backend())

        # Calculate shared secret based on own private key and peer public key.
        shared_key_string = self.lesc_private_key.exchange(ec.ECDH(), lesc_peer_public_key_obj2)

        # before shared_key_string is returned as string, but in python3 it's returned as bytearray
        # so we should treate it as a bytearray

        # shared_key_list = [ord(i) for i in shared_key_string] # no more valid in python3
        log.info("shared_key_string: {}".format(shared_key_string))

        # shared_key_list = [ord(i) for i in shared_key_string] # no more valid in python3
        # shared_key_list = shared_key_list[::-1] # no more valid in python3

        shared_key_list = shared_key_string[::-1]

        log.info("Shared secret list, little endian {}".format(" ".join(["0x{:02X}".format(i) for i in shared_key_list])))

        # Reply to Softdevice with shared key
        lesc_dhkey_array = util.list_to_uint8_array(shared_key_list)
        self.lesc_dhkey = driver.ble_gap_lesc_dhkey_t()
        self.lesc_dhkey.key = lesc_dhkey_array.cast()

        self.ble_driver.ble_gap_lesc_dhkey_reply(self.conn_handle, self.lesc_dhkey)

        self.evt_q.put('lesc_dhkey_request')

    def on_gap_key_pressed(self, ble_driver, conn_handle, keypress_notification):
        log.info('Key pressed event')
        self.evt_q.put('key_pressed')

    def on_gap_passkey_display(self, ble_driver, conn_handle, passkey_display, match_request):
        log.info('Passkey display event')
        self.evt_q.put('passkey_display')

    def on_gap_evt_disconnected(self, ble_driver, conn_handle, reason):
        if reason == BLEHci.conn_failed_to_be_established:
            self.conn_failed = True
        log.info('Disconnected connection handle: {}, reason {}'.format(conn_handle, reason))
        log.info("LTK: {}".format(util.uint8_array_to_list(self.keyset.keys_own.p_enc_key.enc_info.ltk, 16)))
        self.conn_handle = driver.BLE_CONN_HANDLE_INVALID
        self.evt_q.put('disconnected')

    def on_gap_evt_sec_params_request(self, ble_driver, conn_handle, peer_params):
        log.info('sec_params_request event')

        # Generate own private and public lesc keys if lesc is enabled.
        if peer_params.lesc == 1 and self.sec_params.lesc == 1:
            log.info("Generate LE Secure Connection ECDH private and public key.")
            self.lesc_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            lesc_own_public_key = self.lesc_private_key.public_key()

            # Put own lesc public key into keyset.
            lesc_own_public_key_numbers = lesc_own_public_key.public_numbers()
            lesc_own_public_key_array = PublicKey(lesc_own_public_key_numbers.x,
                                                  lesc_own_public_key_numbers.y,
                                                  lesc_own_public_key_numbers.curve).to_c()

            self.lesc_pk_own.pk = lesc_own_public_key_array.cast()

        self.evt_q.put('sec_params_request')

    def on_gap_evt_conn_sec_update(self, ble_driver, conn_handle):
        conn_sec = self.ble_driver.ble_gap_conn_sec_get(conn_handle=conn_handle)
        log.info('Conn_sec_update event: size: {}'.format(conn_sec.encr_key_size))
        log.info('Conn_sec_update event:   sm: {}'.format(conn_sec.sec_mode.sm))
        log.info('Conn_sec_update event:   lv: {}'.format(conn_sec.sec_mode.lv))
        self.evt_q.put('conn_sec_update')
        pass

    def on_gap_evt_auth_status(self, ble_driver, conn_handle, auth_status):
        log.info('Auth_status event: auth_status: {}'.format(auth_status))
        log.info('Auth_status event: LESC: {}'.format(self.keyset.keys_own.p_enc_key.enc_info.lesc))
        log.info("Auth_status event: LTK: {}".format(util.uint8_array_to_list(self.keyset.keys_own.p_enc_key.enc_info.ltk, 16)))

        self.evt_q.put('auth_status')

    def on_evt_tx_complete(self, ble_driver, conn_handle, count):
        # log.info('Tx_complete event')
        pass

    def on_gattc_evt_write_cmd_tx_complete(self, ble_driver, conn_handle, count):
        # log.info('Tx_cmd_complete event')
        pass

    def on_gap_evt_sec_info_request(self, ble_driver, conn_handle, peer_addr, master_id, enc_info, id_info, sign_info):
        log.info('Sec_info_request event  peer_addr: {}'.format(peer_addr.addr))
        # self.ble_driver.ble_gap_sec_info_reply(self, conn_handle, enc_info, None, None)
        self.evt_q.put('sec_info_request')

    def on_gap_evt_sec_request(self, ble_driver, conn_handle, bond, mitm, lesc, keypress):
        log.info('Security request event on conn_handle: {}.'.format(conn_handle))
        log.info('Do nothing')
        self.evt_q.put('sec_request')

    def on_gap_evt_adv_report(self, ble_driver, conn_handle, peer_addr, rssi, adv_type, adv_data):
        if self.conn_in_progress:
            return

        if adv_type == None:
            return

        if BLEAdvData.Types.complete_local_name in adv_data.records:
            dev_name_list = adv_data.records[BLEAdvData.Types.complete_local_name]
        elif BLEAdvData.Types.short_local_name in adv_data.records:
            dev_name_list = adv_data.records[BLEAdvData.Types.short_local_name]
        else:
            dev_name_list = ""

        dev_name = "".join(chr(e) for e in dev_name_list)
        address_string = "".join("{0:02X}".format(byte) for byte in peer_addr.addr)
        log.debug("Received advertisment report, address: 0x{}, device_name: {}, rssi: {}".format(
            address_string, dev_name, rssi))

        # Check if RSSI filter is enabled.
        if self.min_rssi != None:
            if rssi < self.min_rssi:
                return

        if not address_string in self.advertisements:
            self.advertisements[address_string] = {'name': dev_name,
                                                   'records': adv_data.records,
                                                   'rssi' : rssi}

        # Check if address matches, if connecting based on address
        if self.connect_by_BLE_address and (self.last_connected_addr != address_string):
            return

        # Check if device name matches, if connecting based on device name
        if not self.connect_by_BLE_address and (dev_name not in self.conn_targets):
            return

        with self.lock:
            self.conn_in_progress = True
            self.peer_addr = peer_addr
            log.info("Connecting to {} - {}".format(address_string, dev_name))
            self.ble_driver.ble_gap_connect(self.peer_addr,
                                            self.scan_params,
                                            self.conn_params)

        self.last_connected_addr = address_string
    # ----------------------------------------------------------------

    # --------------------------------------------------------------
    # - BLE Gattc event functions
    # --------------------------------------------------------------
    def on_gattc_evt_write_rsp(self, ble_driver, conn_handle, status, error_handle, attr_handle, write_op, offset,
                               data):
        log.info("gattc_write_rsp, connection handle 0x{}".format(conn_handle))
        self.evt_q.put('gattc_write_rsp')

    def on_gattc_evt_read_rsp(self, ble_driver, conn_handle, status, error_handle, attr_handle, offset, data):
        log.info("gattc_read_rsp, connection handle 0x{}".format(self.conn_handle))
        self.evt_q.put('gattc_read_rsp')

    def on_gattc_evt_hvx(self, ble_driver, conn_handle, status, error_handle, attr_handle, hvx_type, data):
        if status != BLEGattStatusCode.success:
            log.error("Error. Handle value notification failed. Gatt status error code {}".format(status))
            return
        else:
            if hvx_type == BLEGattHVXType.notification:
                log.info("Received HVX Notification")
            if hvx_type == BLEGattHVXType.indication:
                log.info("Received HVX Indication")
            else:
                log.error("Received unkonwn HVX type: {}".format(hvx_type))

        data_list_string = "".join("{0:02X}".format(el) for el in data)

        log.info("Received HVX, handle: 0x{}, value: 0x{}".format(attr_handle, data_list_string))
        self.evt_q.put('hvx')
    # ----------------------------------------------------------------

    # --------------------------------------------------------------
    # - BLE Gatts event functions
    # --------------------------------------------------------------
    def on_gatts_evt_hvc(self, ble_driver, status, error_handle, attr_handle):
        log.info("gatts_evt_hvc, connection handle 0x{:04X}".format(self.conn_handle))
        self.evt_q.put('gatts_evt_hvc')

    def on_gatts_evt_write(self, ble_driver, conn_handle, attr_handle, uuid,
                           op, auth_required, offset, length, data):
        log.info("GATTS evt write: UUID: {}, Data: {}, ".format(uuid, data))
        self.evt_q.put('gatts_evt_write')
    # ----------------------------------------------------------------


class SdkBLEEvtID(Enum):
    gap_evt_lesc_dhkey_request        = driver.BLE_GAP_EVT_LESC_DHKEY_REQUEST
    gap_evt_key_pressed               = driver.BLE_GAP_EVT_KEY_PRESSED
    gap_evt_passkey_display           = driver.BLE_GAP_EVT_PASSKEY_DISPLAY


class SdkBLEDriver(BLEDriver):

    def __init__(self, serial_port, baud_rate=115200, auto_flash=False):
        super(SdkBLEDriver, self).__init__(serial_port, baud_rate, auto_flash)

    @wrapt.synchronized(BLEDriver.observer_lock)
    def sync_ble_evt_handler(self, adapter, ble_event):

        evt_id = None
        try:
            evt_id = SdkBLEEvtID(ble_event.header.evt_id)
        except ValueError:
            pass

        try:
            if evt_id == SdkBLEEvtID.gap_evt_lesc_dhkey_request:
                lesc_public_key = ble_event.evt.gap_evt.params.lesc_dhkey_request.p_pk_peer   # ble_gap_lesc_p256_pk_t *
                oobd_req = ble_event.evt.gap_evt.params.lesc_dhkey_request.oobd_req           # uint8

                for obs in self.observers:
                    obs.on_gap_lesc_dhkey_request(ble_driver=self,
                                                  conn_handle=ble_event.evt.gap_evt.conn_handle,
                                                  peer_public_key=lesc_public_key,
                                                  oobd_req=oobd_req)

            elif evt_id == SdkBLEEvtID.gap_evt_key_pressed:
                keypress_notification = ble_event.evt.gap_evt.params.key_pressed.kp_not  # uint8

                for obs in self.observers:
                    obs.on_gap_key_pressed(ble_driver=self,
                                           conn_handle=ble_event.evt.gap_evt.conn_handle,
                                           keypress_notification=keypress_notification)

            elif evt_id == SdkBLEEvtID.gap_evt_passkey_display:
                passkey_display = ble_event.evt.gap_evt.params.passkey_display.passkey  # list[6]
                match_request = ble_event.evt.gap_evt.params.passkey_display.match_request  # uint8

                for obs in self.observers:
                    obs.on_gap_passkey_display(ble_driver=self,
                                               conn_handle=ble_event.evt.gap_evt.conn_handle,
                                               passkey_display=passkey_display,
                                               match_request=match_request)
            else:
                BLEDriver.observer_lock.release()
                # BLEDriver.sync_ble_evt_handler(adapter, ble_event)
                super(SdkBLEDriver, self).sync_ble_evt_handler(adapter, ble_event)

        except Exception as e:
            logger.error("Exception: {}".format(str(e)))
            for line in traceback.extract_tb(sys.exc_info()[2]):
                logger.error(line)
            logger.error("")

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def ble_gap_sec_params_reply(self, conn_handle, sec_status, sec_params, own_keys, peer_keys):
        return driver.sd_ble_gap_sec_params_reply(self.rpc_adapter,
                                                  conn_handle,
                                                  sec_status.value,
                                                  sec_params.to_c() if sec_params else None,
                                                  own_keys)

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def ble_gap_lesc_dhkey_reply(self, conn_handle, p_dhkey):
        return driver.sd_ble_gap_lesc_dhkey_reply(self.rpc_adapter,
                                                  conn_handle,
                                                  p_dhkey)

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def ble_opt_set(self, opt_id, opt):
        return driver.sd_ble_gap_opt_set(self.rpc_adapter, opt_id, opt)

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def ble_gatts_hvx(self, conn_handle, hvx_params):
        return driver.sd_ble_gatts_hvx(self.rpc_adapter, conn_handle, hvx_params)

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def ble_gattc_hv_confirm(self, conn_handle, attr_handle):
        return driver.sd_ble_gattc_hv_confirm(self.rpc_adapter, conn_handle, attr_handle)

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def ble_gap_auth_key_reply(self, conn_handle, key_type, key_value):
        return driver.sd_ble_gap_auth_key_reply(self.rpc_adapter, conn_handle, key_type, key_value)


class SdkBLEAdapter(BLEAdapter):

    def __init__(self, ble_driver_a):
        super(SdkBLEAdapter, self).__init__(ble_driver_a)
        self.attempts = 0

    @NordicSemiErrorCheck(expected=BLEGattStatusCode.success)
    def enable_notification(self, conn_handle, uuid, indication=False):
        cccd_list = [2, 0] if indication else [1, 0]

        handle = self.db_conns[conn_handle].get_cccd_handle(uuid)

        if handle is None:
            raise NordicSemiException('CCCD not found')

        write_params = BLEGattcWriteParams(BLEGattWriteOperation.write_req,
                                           BLEGattExecWriteFlag.unused,
                                           handle,
                                           cccd_list,
                                           0)

        self.driver.ble_gattc_write(conn_handle, write_params)
        result = self.evt_sync[conn_handle].wait(evt=BLEEvtID.gattc_evt_write_rsp)
        return result['status']

    def read_char_cccd(self, conn_handle, uuid):
        """ Read the value of the cccd of a given characteristic.

        Args:
            uuid:  UUID of characteristic as BLEUUID type.

        Returns:   CCCD data as list.

        """
        assert isinstance(uuid, BLEUUID), 'Invalid argument type'

        cccd_handle = self.db_conns[conn_handle].get_cccd_handle(uuid)
        if cccd_handle is None:
            raise NordicSemiException('CCCD not found')

        self.driver.ble_gattc_read(conn_handle, cccd_handle, 0)
        result = self.evt_sync[conn_handle].wait(evt=BLEEvtID.gattc_evt_read_rsp)
        gatt_res = result['status']
        if gatt_res == BLEGattStatusCode.success:
            return result['data']
        else:
            return None

    def conn_param_update(self, conn_handle, conn_params):
        self.attempts = 0
        try:
            self.driver.ble_gap_conn_param_update(conn_handle, conn_params)
        except NordicSemiException as e:
            while e.args[1] == driver.NRF_ERROR_BUSY:
                self.attempts += 1
                if self.attempts < 4:
                    log.error("conn_param_update failed after 3 attempts")
                    raise e
                log.info("Conn_param_update NRF_BUSY handled")
                t = threading.Timer(0.5, self.ble_driver.ble_gap_conn_param_update, args=(conn_handle, conn_params))
                t.start()
            else:
                raise

    @wrapt.synchronized(BLEAdapter.observer_lock)
    def on_gap_lesc_dhkey_request(self, ble_driver, conn_handle, **kwargs):
        pass
        # self.evt_sync[conn_handle].notify(evt=SdkBLEEvtID.gap_evt_lesc_dhkey_request, data=kwargs)

    @wrapt.synchronized(BLEAdapter.observer_lock)
    def on_gap_key_pressed(self, ble_driver, conn_handle, **kwargs):
        pass
        # self.evt_sync[conn_handle].notify(evt=SdkBLEEvtID.gap_evt_key_pressed, data=kwargs)

    @wrapt.synchronized(BLEAdapter.observer_lock)
    def on_gap_passkey_display(self, ble_driver, conn_handle, **kwargs):
        pass
        # self.evt_sync[conn_handle].notify(evt=SdkBLEEvtID.gap_evt_passkey_display, data=kwargs)

    @wrapt.synchronized(BLEAdapter.observer_lock)
    def on_gattc_evt_hvx(self, ble_driver, conn_handle, status, error_handle, attr_handle, hvx_type, data):
        if status != BLEGattStatusCode.success:
            logger.error("Error. Handle value notification failed. Status {}.".format(status))
            return

        if hvx_type == BLEGattHVXType.notification:
            uuid = self.db_conns[conn_handle].get_char_uuid(attr_handle)
            if uuid is None:
                log.error('UUID not found')
                return

            for obs in self.observers:
                obs.on_notification(ble_adapter=self,
                                    conn_handle=conn_handle,
                                    uuid=uuid,
                                    data=data)

        elif hvx_type == BLEGattHVXType.indication:
            uuid = self.db_conns[conn_handle].get_char_uuid(attr_handle)

            for obs in self.observers:
                obs.on_indication(ble_adapter=self,
                                  conn_handle=conn_handle,
                                  uuid=uuid,
                                  data=data)

            self.driver.ble_gattc_hv_confirm(conn_handle, attr_handle)