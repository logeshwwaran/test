import struct
import time
import logging
from datetime import datetime
from Crypto.Cipher import AES
from Queue import Queue, Empty
from bluepy.btle import Peripheral, DefaultDelegate, ADDR_TYPE_RANDOM, BTLEException
import crc16
import os
import struct

from constants import UUIDS, AUTH_STATES, QUEUE_TYPES


class AuthenticationDelegate(DefaultDelegate):

    """This Class inherits DefaultDelegate to handle the authentication process."""

    def __init__(self, device):
        DefaultDelegate.__init__(self)
        self.device = device

    def handleNotification(self, hnd, data):
        if hnd == self.device._char_auth.getHandle():
            if data[:3] == b'\x10\x01\x01':
                self.device._req_rdn()
            elif data[:3] == b'\x10\x01\x04':
                self.device.state = AUTH_STATES.KEY_SENDING_FAILED
            elif data[:3] == b'\x10\x02\x01':
                # 16 bytes
                random_nr = data[3:]
                self.device._send_enc_rdn(random_nr)
            elif data[:3] == b'\x10\x02\x04':
                self.device.state = AUTH_STATES.REQUEST_RN_ERROR
            elif data[:3] == b'\x10\x03\x01':
                self.device.state = AUTH_STATES.AUTH_OK
            elif data[:3] == b'\x10\x03\x04':
                self.device.status = AUTH_STATES.ENCRIPTION_KEY_FAILED
                self.device._send_key()
            else:
                self.device.state = AUTH_STATES.AUTH_FAILED
        elif hnd == self.device._char_heart_measure.getHandle():
            self.device.queue.put((QUEUE_TYPES.HEART, data))
        elif hnd == 0x38:
            # Not sure about this, need test
            if len(data) == 20 and struct.unpack('b', data[0])[0] == 1:
                self.device.queue.put((QUEUE_TYPES.RAW_ACCEL, data))
            elif len(data) == 16:
                self.device.queue.put((QUEUE_TYPES.RAW_HEART, data))
        else:
            self.device._log.error("Unhandled Response " + hex(hnd) + ": " +
                                   str(data.encode("hex")) + " len:" + str(len(data)))


class MiBand3(Peripheral):
    _KEY = b'\x01\x23\x45\x67\x89\x01\x22\x23\x34\x45\x56\x67\x78\x89\x90\x02'
    _send_key_cmd = struct.pack('<18s', b'\x01\x08' + _KEY)
    _send_rnd_cmd = struct.pack('<2s', b'\x02\x08')
    _send_enc_key = struct.pack('<2s', b'\x03\x08')

    def __init__(self, mac_address, timeout=0.5, debug=False):
        FORMAT = '%(asctime)-15s %(name)s (%(levelname)s) > %(message)s'
        logging.basicConfig(format=FORMAT)
        log_level = logging.WARNING if not debug else logging.DEBUG
        self._log = logging.getLogger(self.__class__.__name__)
        self._log.setLevel(log_level)

        self._log.info('Connecting to ' + mac_address)
        Peripheral.__init__(self, mac_address, addrType=ADDR_TYPE_RANDOM)
        self._log.info('Connected')

        self.timeout = timeout
        self.mac_address = mac_address
        self.state = None
        self.queue = Queue()
        self.heart_measure_callback = None
        self.heart_raw_callback = None
        self.accel_raw_callback = None

        self.svc_1 = self.getServiceByUUID(UUIDS.SERVICE_MIBAND1)
        self.svc_2 = self.getServiceByUUID(UUIDS.SERVICE_MIBAND2)
        self.svc_heart = self.getServiceByUUID(UUIDS.SERVICE_HEART_RATE)

        self._char_auth = self.svc_2.getCharacteristics(UUIDS.CHARACTERISTIC_AUTH)[0]
        self._desc_auth = self._char_auth.getDescriptors(forUUID=UUIDS.NOTIFICATION_DESCRIPTOR)[0]

        self._char_heart_ctrl = self.svc_heart.getCharacteristics(UUIDS.CHARACTERISTIC_HEART_RATE_CONTROL)[0]
        self._char_heart_measure = self.svc_heart.getCharacteristics(UUIDS.CHARACTERISTIC_HEART_RATE_MEASURE)[0]

        # Enable auth service notifications on startup
        self._auth_notif(True)
        # Let band to settle
        self.waitForNotifications(0.1)

    # Auth helpers ######################################################################

    def _auth_notif(self, enabled):
        if enabled:
            self._log.info("Enabling Auth Service notifications status...")
            self._desc_auth.write(b"\x01\x00", True)
        elif not enabled:
            self._log.info("Disabling Auth Service notifications status...")
            self._desc_auth.write(b"\x00\x00", True)
        else:
            self._log.error("Something went wrong while changing the Auth Service notifications status...")

    def _encrypt(self, message):
        aes = AES.new(self._KEY, AES.MODE_ECB)
        return aes.encrypt(message)

    def _send_key(self):
        self._log.info("Sending Key...")
        self._char_auth.write(self._send_key_cmd)
        self.waitForNotifications(self.timeout)

    def _req_rdn(self):
        self._log.info("Requesting random number...")
        self._char_auth.write(self._send_rnd_cmd)
        self.waitForNotifications(self.timeout)

    def _send_enc_rdn(self, data):
        self._log.info("Sending encrypted random number")
        cmd = self._send_enc_key + self._encrypt(data)
        send_cmd = struct.pack('<18s', cmd)
        self._char_auth.write(send_cmd)
        self.waitForNotifications(self.timeout)

    # Parse helpers ###################################################################

    def _parse_raw_heart(self, bytes):
        res = struct.unpack('HHHHHHH', bytes[2:])
        return res



    # Queue ###################################################################

    def _get_from_queue(self, _type):
        try:
            res = self.queue.get(False)
        except Empty:
            return None
        if res[0] != _type:
            self.queue.put(res)
            return None
        return res[1]

    def _parse_queue(self):
        while True:
            try:
                res = self.queue.get(False)
                _type = res[0]
                if self.heart_measure_callback and _type == QUEUE_TYPES.HEART:
                    self.heart_measure_callback(struct.unpack('bb', res[1])[1])
                elif self.heart_raw_callback and _type == QUEUE_TYPES.RAW_HEART:
                    self.heart_raw_callback(self._parse_raw_heart(res[1]))
                elif self.accel_raw_callback and _type == QUEUE_TYPES.RAW_ACCEL:
                    self.accel_raw_callback(self._parse_raw_accel(res[1]))
            except Empty:
                break

    # API ####################################################################


    def authenticate(self):
        self.setDelegate(AuthenticationDelegate(self))
        self._req_rdn()

        while True:
            self.waitForNotifications(0.1)
            if self.state == AUTH_STATES.AUTH_OK:
                self._log.info('Authenticated')
                return True
            elif self.state is None:
                continue

            self._log.error(self.state)
            return False





    def start_raw_data_realtime(self, heart_measure_callback=None, heart_raw_callback=None, accel_raw_callback=None):
            char_m = self.svc_heart.getCharacteristics(UUIDS.CHARACTERISTIC_HEART_RATE_MEASURE)[0]
            char_d = char_m.getDescriptors(forUUID=UUIDS.NOTIFICATION_DESCRIPTOR)[0]
            char_ctrl = self.svc_heart.getCharacteristics(UUIDS.CHARACTERISTIC_HEART_RATE_CONTROL)[0]

            if heart_measure_callback:
                self.heart_measure_callback = heart_measure_callback
            if heart_raw_callback:
                self.heart_raw_callback = heart_raw_callback
            if accel_raw_callback:
                self.accel_raw_callback = accel_raw_callback

            char_sensor = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_SENSOR)[0]

            # stop heart monitor continues & manual
            char_ctrl.write(b'\x15\x02\x00', True)
            char_ctrl.write(b'\x15\x01\x00', True)
            # WTF
            # char_sens_d1.write(b'\x01\x00', True)
            # enabling accelerometer & heart monitor raw data notifications
            char_sensor.write(b'\x01\x03\x19')
            # IMO: enablee heart monitor notifications
            char_d.write(b'\x01\x00', True)
            # start hear monitor continues
            char_ctrl.write(b'\x15\x01\x01', True)
            # WTF
            char_sensor.write(b'\x02')
            t = time.time()
            while True:
                self.waitForNotifications(0.5)
                self._parse_queue()
                # send ping request every 12 sec
                if (time.time() - t) >= 12:
                    char_ctrl.write(b'\x16', True)
                    t = time.time()

    def stop_realtime(self):
            char_m = self.svc_heart.getCharacteristics(UUIDS.CHARACTERISTIC_HEART_RATE_MEASURE)[0]
            char_d = char_m.getDescriptors(forUUID=UUIDS.NOTIFICATION_DESCRIPTOR)[0]
            char_ctrl = self.svc_heart.getCharacteristics(UUIDS.CHARACTERISTIC_HEART_RATE_CONTROL)[0]

            char_sensor1 = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_HZ)[0]
            char_sens_d1 = char_sensor1.getDescriptors(forUUID=UUIDS.NOTIFICATION_DESCRIPTOR)[0]

            char_sensor2 = self.svc_1.getCharacteristics(UUIDS.CHARACTERISTIC_SENSOR)[0]

            # stop heart monitor continues
            char_ctrl.write(b'\x15\x01\x00', True)
            char_ctrl.write(b'\x15\x01\x00', True)
            # IMO: stop heart monitor notifications
            char_d.write(b'\x00\x00', True)
            # WTF
            char_sensor2.write(b'\x03')
            # IMO: stop notifications from sensors
            char_sens_d1.write(b'\x00\x00', True)

            self.heart_measure_callback = None
            self.heart_raw_callback = None
            self.accel_raw_callback = None
