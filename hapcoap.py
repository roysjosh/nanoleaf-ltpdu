import argparse
import asyncio
import logging
import struct
import tlv8
import uuid

from aiocoap import POST, VALID, Context, Message, resource
# XXX figure out why pairing fails when using published version
# XXX use local copy from github for now
#from aiohomekit.crypto.srp import SrpClient
from aiohomekit.model import Accessory
from aiohomekit.model.characteristics import Characteristic, CharacteristicsTypes
from aiohomekit.model.services import Service
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from srp import SrpClient
from typing import cast
from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

class HAP_PAIRING_ERRORS:
    UNKNOWN = 1
    AUTHENTICATION = 2
    MAX_PEERS = 4
    MAX_TRIES = 5
    UNAVAILABLE = 6
    BUSY = 7

class HAP_PAIRING_METHODS:
    PAIR_SETUP = 0
    PAIR_SETUP_WITH_AUTH = 1
    PAIR_VERIFY = 2
    ADD_PAIRING = 3
    REMOVE_PAIRING = 4
    LIST_PAIRINGS = 5
    PAIR_RESUME = 6

class HAP_PDU_OPCODES:
    HAP_CHARACTERISTIC_SIGNATURE_READ = 0x01
    HAP_CHARACTERISTIC_WRITE = 0x02
    HAP_CHARACTERISTIC_READ = 0x03
    HAP_CHARACTERISTIC_TIMEDWRITE = 0x04
    HAP_CHARACTERISTIC_TIMEDREAD = 0x05
    HAP_SERVICE_SIGNATURE_READ = 0x06
    HAP_CHARACTERISTIC_CONFIGURATION = 0x07
    HAP_PROTOCOL_CONFIGURATION = 0x08
    UNK_09_READ_GATT = 0x09
    UNK_0A = 0x0A
    UNK_0B_SUBSCRIBE = 0x0B
    UNK_0C = 0x0C
    HAP_TOKEN_REQUEST = 0x10
    HAP_TOKEN_UPDATE_REQUEST = 0x11
    HAP_INFO_REQUEST = 0x12

class HAP_PDU_TLV_TAGS:
    SEPARATOR = 0x00
    HAP_PARAM_VALUE = 0x01
    HAP_PARAM_ADDITIONAL_AUTHORIZATION_DATA = 0x02
    HAP_PARAM_ORIGIN = 0x03
    HAP_PARAM_CHARACTERISTIC_TYPE = 0x04
    HAP_PARAM_CHARACTERISTIC_INSTANCE_ID = 0x05
    HAP_PARAM_SERVICE_TYPE = 0x06
    HAP_PARAM_SERVICE_INSTANCE_ID = 0x07
    HAP_PARAM_TTL = 0x08
    HAP_PARAM_RETURN_RESPONSE = 0x09
    HAP_PARAM_HAP_CHARACTERISTIC_PROPERTIES_DESCRIPTOR = 0x0A
    HAP_PARAM_GATT_USER_DESCRIPTION_DESCRIPTOR = 0x0B
    HAP_PARAM_GATT_PRESENTATION_FORMAT_DESCRIPTOR = 0x0C
    HAP_PARAM_GATT_VALID_RANGE = 0x0D
    HAP_PARAM_HAP_STEP_VALUE_DESCRIPTOR = 0x0E
    HAP_PARAM_HAP_SERVICE_PROPERTIES = 0x0F
    HAP_PARAM_HAP_LINKED_SERVICES = 0x10
    HAP_PARAM_HAP_VALID_VALUES_DESCRIPTOR = 0x11
    HAP_PARAM_HAP_VALID_VALUES_RANGE_DESCRIPTOR = 0x12
    UNK_13_CHARACTERISTIC = 0x13
    UNK_14_CHARACTERISTICS = 0x14
    UNK_15_SERVICE = 0x15
    UNK_16_SERVICES = 0x16
    UNK_17 = 0x17
    UNK_18 = 0x18
    UNK_19 = 0x19
    UNK_1A = 0x1A

class HAP_TLV_TAGS:
    METHOD = 0
    IDENTIFIER = 1
    SALT = 2
    PUBLIC_KEY = 3
    PROOF = 4
    ENCRYPTED_DATA = 5
    STATE = 6
    ERROR_CODE = 7
    SIGNATURE = 10
    PERMISSIONS = 11

def decode_pdu_03(buf):
    expected_structure = {
        HAP_PDU_TLV_TAGS.HAP_PARAM_VALUE: tlv8.DataType.BYTES,
    }
    return tlv8.decode(buf, expected_structure).first_by_id(HAP_PDU_TLV_TAGS.HAP_PARAM_VALUE).data

def decode_pdu_09(buf):
    expected_structure = {
        HAP_PDU_TLV_TAGS.UNK_18: {
            HAP_PDU_TLV_TAGS.UNK_19: {
                HAP_PDU_TLV_TAGS.UNK_16_SERVICES: {
                    HAP_PDU_TLV_TAGS.SEPARATOR: tlv8.DataType.BYTES,
                    HAP_PDU_TLV_TAGS.UNK_15_SERVICE: {
                        HAP_PDU_TLV_TAGS.HAP_PARAM_ADDITIONAL_AUTHORIZATION_DATA: tlv8.DataType.BYTES,
                        HAP_PDU_TLV_TAGS.HAP_PARAM_SERVICE_TYPE: tlv8.DataType.BYTES, # can be a UUID
                        HAP_PDU_TLV_TAGS.HAP_PARAM_SERVICE_INSTANCE_ID: tlv8.DataType.INTEGER,
                        HAP_PDU_TLV_TAGS.HAP_PARAM_HAP_SERVICE_PROPERTIES: tlv8.DataType.BYTES,
                        HAP_PDU_TLV_TAGS.HAP_PARAM_HAP_LINKED_SERVICES: tlv8.DataType.BYTES, # XXX list?
                        HAP_PDU_TLV_TAGS.UNK_14_CHARACTERISTICS: {
                            HAP_PDU_TLV_TAGS.SEPARATOR: tlv8.DataType.BYTES,
                            HAP_PDU_TLV_TAGS.UNK_13_CHARACTERISTIC: {
                                HAP_PDU_TLV_TAGS.HAP_PARAM_CHARACTERISTIC_TYPE: tlv8.DataType.BYTES, # can be a UUID
                                HAP_PDU_TLV_TAGS.HAP_PARAM_CHARACTERISTIC_INSTANCE_ID: tlv8.DataType.INTEGER,
                                HAP_PDU_TLV_TAGS.HAP_PARAM_HAP_CHARACTERISTIC_PROPERTIES_DESCRIPTOR: tlv8.DataType.INTEGER,
                                HAP_PDU_TLV_TAGS.HAP_PARAM_GATT_PRESENTATION_FORMAT_DESCRIPTOR: tlv8.DataType.BYTES,
                                HAP_PDU_TLV_TAGS.HAP_PARAM_HAP_VALID_VALUES_DESCRIPTOR: tlv8.DataType.BYTES,
                                HAP_PDU_TLV_TAGS.HAP_PARAM_HAP_VALID_VALUES_RANGE_DESCRIPTOR: tlv8.DataType.BYTES,
                            },
                        },
                    },
                },
                HAP_PDU_TLV_TAGS.UNK_1A: tlv8.DataType.BYTES,
            },
        },
    }
    return tlv8.decode(buf, expected_structure)

def decode_list_pairings_response(buf):
    expected_structure = {
        HAP_PDU_TLV_TAGS.HAP_PARAM_VALUE: {
            HAP_TLV_TAGS.STATE: tlv8.DataType.INTEGER,
            HAP_TLV_TAGS.IDENTIFIER: tlv8.DataType.BYTES,
            HAP_TLV_TAGS.PUBLIC_KEY: tlv8.DataType.BYTES,
            HAP_TLV_TAGS.PERMISSIONS: tlv8.DataType.INTEGER,
        },
    }
    return tlv8.decode(buf, expected_structure)

def decode_tlv(buf):
    expected_structure = {
        HAP_TLV_TAGS.METHOD: tlv8.DataType.INTEGER,
        HAP_TLV_TAGS.IDENTIFIER: tlv8.DataType.BYTES,
        HAP_TLV_TAGS.SALT: tlv8.DataType.BYTES,
        HAP_TLV_TAGS.PUBLIC_KEY: tlv8.DataType.BYTES,
        HAP_TLV_TAGS.PROOF: tlv8.DataType.BYTES,
        HAP_TLV_TAGS.ENCRYPTED_DATA: tlv8.DataType.BYTES,
        HAP_TLV_TAGS.STATE: tlv8.DataType.INTEGER,
        HAP_TLV_TAGS.ERROR_CODE: tlv8.DataType.INTEGER,
        HAP_TLV_TAGS.SIGNATURE: tlv8.DataType.BYTES,
        HAP_TLV_TAGS.PERMISSIONS: tlv8.DataType.BYTES,
    }
    decoded = tlv8.decode(buf, expected_structure)
    print(tlv8.format_string(decoded))
    return { tlv.type_id: tlv for tlv in decoded }

pduStatusMap = list( (
    'Success',
    'Unsupported PDU',
    'Max-Procedures',
    'Insufficient Authorization',
    'Invalid Instance ID',
    'Insufficient Authentication',
    'Invalid Request',
) )

class PduCharacteristicProperties(object):
    def __init__(self, property_int):
        self.property_int = property_int
        self.supports_read = property_int & 0x0001
        self.supports_write = property_int & 0x0002
        self.supports_additional_authorization_data = property_int & 0x0004
        self.requires_hap_characteristic_timed_write_procedure = property_int & 0x0008
        self.supports_secure_reads = property_int & 0x0010
        self.supports_secure_writes = property_int & 0x0020
        self.hidden_from_user = property_int & 0x0040
        self.notifies_events_in_connected_state = property_int & 0x0080
        self.notifies_events_in_disconnected_state = property_int & 0x0100
        self.supports_broadcast_notify = property_int & 0x0200

    def __repr__(self):
        return '{"aa":%s,"tw":%s,"pr":%s,"pw":%s,"hd":%s,"ev":%s}' % (
            self.supports_additional_authorization_data and 'true' or 'false',
            self.requires_hap_characteristic_timed_write_procedure and 'true' or 'false',
            self.supports_secure_reads and 'true' or 'false',
            self.supports_secure_writes and 'true' or 'false',
            self.hidden_from_user and 'true' or 'false',
            self.notifies_events_in_connected_state and 'true' or 'false',
        )

    def to_dict(self):
        result = list()
        if self.supports_secure_reads:
            result.append('pr')
        if self.supports_secure_writes:
            result.append('pw')
        if self.notifies_events_in_connected_state:
            result.append('ev')
        if self.supports_additional_authorization_data:
            result.append('aa')
        if self.requires_hap_characteristic_timed_write_procedure:
            result.append('tw')
        if self.hidden_from_user:
            result.append('hd')
        return result

class PduCharacteristic(object):
    def __init__(self, characteristic_tlv):
        self.type = characteristic_tlv.first_by_id(HAP_PDU_TLV_TAGS.HAP_PARAM_CHARACTERISTIC_TYPE)
        if self.type:
            self.type = int.from_bytes(self.type.data, 'little')

        self.iid = characteristic_tlv.first_by_id(HAP_PDU_TLV_TAGS.HAP_PARAM_CHARACTERISTIC_INSTANCE_ID)
        if self.iid:
            self.iid = self.iid.data

        self.properties = characteristic_tlv.first_by_id(HAP_PDU_TLV_TAGS.HAP_PARAM_HAP_CHARACTERISTIC_PROPERTIES_DESCRIPTOR)
        if self.properties:
            self.properties = PduCharacteristicProperties(self.properties.data)

        self.presentation_format = characteristic_tlv.first_by_id(HAP_PDU_TLV_TAGS.HAP_PARAM_GATT_PRESENTATION_FORMAT_DESCRIPTOR)
        if self.presentation_format:
            self.presentation_format = bytes(self.presentation_format.data)
            (self.pf_format, self.pf_unit) = struct.unpack('<BxHxxx', self.presentation_format)

        self.value = None

    def __repr__(self):
        return '{"type":"%X","iid":"%s","perms":%s}' % (
            self.type and self.type or '',
            self.iid and str(self.iid) or '',
            repr(self.properties)
        )

    def get_format(self):
        if self.pf_format == 0x01:
            return 'bool'
        elif self.pf_format in [0x04, 0x06, 0x08, 0x0A, 0x10]:
            return 'int'
        elif self.pf_format == 0x14:
            return 'float'
        elif self.pf_format == 0x19:
            return 'string'
        elif self.pf_format == 0x1B:
            return 'data'
        return 'unknown'

    def get_unit(self):
        if self.pf_unit == 0x272F:
            return 'celsius'
        elif self.pf_unit == 0x2763:
            return 'arcdegrees'
        elif self.pf_unit == 0x27AD:
            return 'percentage'
        elif self.pf_unit == 0x2700:
            return 'unitless'
        elif self.pf_unit == 0x2731:
            return 'lux'
        elif self.pf_unit == 0x2703:
            return 'seconds'
        return 'unknown'

    def get_value(self):
        if not self.pf_format:
            return self.value
        elif self.pf_format == 0x01:
            val = struct.unpack('<B', self.value)[0]
            return bool(val)
        elif self.pf_format == 0x04:
            return struct.unpack('<B', self.value)[0]
        elif self.pf_format == 0x06:
            return struct.unpack('<H', self.value)[0]
        elif self.pf_format == 0x08:
            return struct.unpack('<L', self.value)[0]
        elif self.pf_format == 0x0A:
            return struct.unpack('<Q', self.value)[0]
        elif self.pf_format == 0x10:
            return struct.unpack('<l', self.value)[0]
        elif self.pf_format == 0x14:
            return struct.unpack('<f', self.value)[0]
        elif self.pf_format == 0x19:
            return bytes.decode(self.value)
        elif self.pf_format == 0x1B:
            # ???
            return self.value.hex()
        else:
            return self.value

    def set_value(self, value):
        if not self.pf_format:
            self.value = value
        elif self.pf_format == 0x01:
            self.value = b'\x01' if value else b'\x00'
        elif self.pf_format == 0x04:
            self.value = struct.pack('<B', value)
        elif self.pf_format == 0x06:
            self.value = struct.pack('<H', value)
        elif self.pf_format == 0x08:
            self.value = struct.pack('<L', value)
        elif self.pf_format == 0x0A:
            self.value = struct.pack('<Q', value)
        elif self.pf_format == 0x10:
            self.value = struct.pack('<l', value)
        elif self.pf_format == 0x14:
            self.value = struct.pack('<f', value)
        elif self.pf_format == 0x19:
            self.value = value.encode()
        elif self.pf_format == 0x1B:
            # ???
            self.value = bytes.fromhex(value)
        else:
            self.value = value

    def to_dict(self):
        result = {
            'type': '%X' % (self.type,),
            'iid': self.iid,
            'perms': self.properties.to_dict(),
        }

        if self.pf_format != None:
            result['format'] = self.get_format()

        if self.pf_unit != None and self.pf_unit != 0x2700:
            result['unit'] = self.get_unit()

        if self.value != None:
            result['value'] = self.get_value()

        return result

class PduService(object):
    def __init__(self, service_tlv):
        self.service_type = service_tlv.first_by_id(HAP_PDU_TLV_TAGS.HAP_PARAM_SERVICE_TYPE)
        if self.service_type:
            self.service_type = int.from_bytes(self.service_type.data, 'little')

        self.service_instance_id = service_tlv.first_by_id(HAP_PDU_TLV_TAGS.HAP_PARAM_SERVICE_INSTANCE_ID)
        if self.service_instance_id:
            self.service_instance_id = self.service_instance_id.data

        self.characteristics = [PduCharacteristic(characteristic_tlv.data) for characteristic_tlv in service_tlv.first_by_id(HAP_PDU_TLV_TAGS.UNK_14_CHARACTERISTICS).data.by_id(HAP_PDU_TLV_TAGS.UNK_13_CHARACTERISTIC)]

    def __repr__(self):
        return '{"type":"%X","iid":"%s","characteristics":%s}' % (
            self.service_type and self.service_type or '',
            self.service_instance_id and str(self.service_instance_id) or '',
            repr(self.characteristics)
        )

    def to_dict(self):
        return {
            'type': '%X' % (self.service_type,),
            'iid': self.service_instance_id,
            'characteristics': [characteristic.to_dict() for characteristic in self.characteristics],
        }

    def find_characteristic_by_iid(self, iid):
        for characteristic in self.characteristics:
            if characteristic.iid == iid:
                return characteristic
        return None

    def find_characteristic_by_type(self, characteristic_type):
        for characteristic in self.characteristics:
            if characteristic.type == characteristic_type:
                return characteristic
        return None

class PduAccessoryInfo(object):
    def __init__(self, aid, services_tlv):
        self.aid = aid
        self.services = [PduService(service_tlv.data) for service_tlv in services_tlv.by_id(HAP_PDU_TLV_TAGS.UNK_15_SERVICE)]

    def __repr__(self):
        return '{"aid":' + self.aid + ',"services":' + repr(self.services) + '}'

    def to_dict(self):
        return {
            'aid': self.aid,
            'services': [service.to_dict() for service in self.services],
        }

    def find_characteristic_by_iid(self, iid):
        for service in self.services:
            characteristic = service.find_characteristic_by_iid(iid)
            if characteristic:
                return characteristic
        return None

    def find_service_by_type(self, service_type):
        for service in self.services:
            if service.service_type == service_type:
                return service
        return None

    def find_service_characteristic_by_type(self, service_type, characteristic_type):
        service = self.find_service_by_type(service_type)
        if service:
            return service.find_characteristic_by_type(characteristic_type)
        return None

class RootResource(resource.Resource):
    def __init__(self):
        super().__init__()

    async def render_put(self, request):
        print('PUT HAP PDU')

        enc_ctx = my_sessions[request.remote.hostinfo]
        payload = enc_ctx.decrypt_event(request.payload)
        print('... %s' % (payload.hex(),))

        return Message(code=VALID)

my_sessions = dict()

class EncCtx(object):
    def __init__(self, recvCtx, sendCtx, eventCtx):
        self.recvCtr = 0
        self.recvCtx = recvCtx
        self.sendCtr = 0
        self.sendCtx = sendCtx
        self.eventCtr = 0
        self.eventCtx = eventCtx

    def decrypt(self, enc_data):
        #print('RECV CTR %d' % (self.recvCtr,))
        dec_data = self.recvCtx.decrypt(struct.pack('=4xQ', self.recvCtr), enc_data, b'')
        self.recvCtr += 1
        return dec_data

    def decrypt_event(self, enc_data):
        #print('EVENT CTR %d' % (self.eventCtr,))
        dec_data = self.eventCtx.decrypt(struct.pack('=4xQ', self.eventCtr), enc_data, b'')
        self.eventCtr += 1
        return dec_data

    def encrypt(self, dec_data):
        #print('SEND CTR %d' % (self.sendCtr,))
        enc_data = self.sendCtx.encrypt(struct.pack('=4xQ', self.sendCtr), dec_data, b'')
        self.sendCtr += 1
        return enc_data

class HAPThreadDevice:
    def __init__(self, address, properties):
        self.address = address
        self.properties = properties
        self.aeadCtx = None # during pairing
        self.encCtx = None # normal comms
        self.coapClient = None

    def __derive_key(self, seed, salt, info):
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            info=info,
        )
        return hkdf.derive(seed)

    async def do_pair_setup(self, pin):
        self.coapClient = await Context.create_client_context()
        uri = "coap://%s/1" % (self.address)

        # pair-setup M1
        payload = tlv8.encode([
            tlv8.Entry(HAP_TLV_TAGS.METHOD, HAP_PAIRING_METHODS.PAIR_SETUP_WITH_AUTH),
            tlv8.Entry(HAP_TLV_TAGS.STATE, 1),
        ])
        #print('M1 request payload: %s' % (payload.hex(),))
        print('M1 ->')
        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response
        #print('M2 response CoAP(code:%s) payload: %s' % (response.code, response.payload.hex()))
        print('<- M2')

        # pair-setup M2
        m2 = decode_tlv(response.payload)
        #print('M2 %r' % (m2,))

        if HAP_TLV_TAGS.ERROR_CODE in m2:
            print('Error! Code=%d' % (m2[HAP_TLV_TAGS.ERROR_CODE].data,))

        if HAP_TLV_TAGS.STATE not in m2 or m2[HAP_TLV_TAGS.STATE].data != 2:
            print('Error! Bad sequence.')
            return None

        if HAP_TLV_TAGS.PUBLIC_KEY not in m2 or HAP_TLV_TAGS.SALT not in m2:
            print('Error! Missing M2 parameters.')
            return None

        salt = bytes(m2[HAP_TLV_TAGS.SALT].data)
        srpB = bytes(m2[HAP_TLV_TAGS.PUBLIC_KEY].data)

        # pair-setup M3
        srp_client = SrpClient('Pair-Setup', pin)
        srp_client.set_salt(salt)
        srp_client.set_server_public_key(srpB)
        srpA = srp_client.get_public_key()
        srpM = srp_client.get_proof()

        if srpM is None:
            print('Error! SRP M is None.')
            return None

        payload = tlv8.encode([
            tlv8.Entry(HAP_TLV_TAGS.STATE, 3),
            tlv8.Entry(HAP_TLV_TAGS.PUBLIC_KEY, SrpClient.to_byte_array(srpA)),
            tlv8.Entry(HAP_TLV_TAGS.PROOF, SrpClient.to_byte_array(srpM)),
        ])
        #print('M3 request payload: %s' % (payload.hex(),))
        print('M3 ->')
        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response
        #print('M4 response CoAP(code:%s) payload: %s' % (response.code, response.payload.hex()))
        print('<- M4')

        # pair-setup M4
        m4 = decode_tlv(response.payload)
        #print('M4 %r' % (m4,))

        if HAP_TLV_TAGS.ERROR_CODE in m4:
            print('Error! Code=%d' % (m4[HAP_TLV_TAGS.ERROR_CODE].data,))
            return None

        if HAP_TLV_TAGS.STATE not in m4 or m4[HAP_TLV_TAGS.STATE].data != 4:
            print('Error! Bad sequence.')
            return None

        if HAP_TLV_TAGS.PROOF not in m4:
            print('Error! Missing M4 parameters.')
            return None

        srpHAMK = m4[HAP_TLV_TAGS.PROOF].data

        if not srp_client.verify_servers_proof(srpHAMK):
            print('Error! SRP authentication failed.')
            return None

        session_key = srp_client.get_session_key()
        expanded_key = self.__derive_key(SrpClient.to_byte_array(session_key), b'Pair-Setup-Encrypt-Salt', b'Pair-Setup-Encrypt-Info')
        self.aeadCtx = ChaCha20Poly1305(expanded_key)

        # encrypted data is optional
        if HAP_TLV_TAGS.ENCRYPTED_DATA in m4:
            encData = bytes(m4[HAP_TLV_TAGS.ENCRYPTED_DATA].data)
            decData = self.aeadCtx.decrypt(b'\0\0\0\0PS-Msg04', encData, b'')
            decTlv = decode_tlv(decData)
            #print('M4 inner %r' % (decTlv,))
            #for k in decTlv.keys():
            #    print('- %r = %s' % (k, bytes(decTlv[k].data).hex()))

        # pair-setup M5
        expanded_key = self.__derive_key(SrpClient.to_byte_array(session_key), b'Pair-Setup-Controller-Sign-Salt', b'Pair-Setup-Controller-Sign-Info')

        my_uuid = str(uuid.uuid4()).encode('ascii')
        my_ltsk = Ed25519PrivateKey.generate()
        my_ltpk = my_ltsk.public_key()
        my_ltpk_bytes = my_ltpk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        my_info = expanded_key + my_uuid + my_ltpk_bytes

        info_sig = my_ltsk.sign(my_info)

        inner_payload = tlv8.encode([
            tlv8.Entry(HAP_TLV_TAGS.IDENTIFIER, my_uuid),
            tlv8.Entry(HAP_TLV_TAGS.PUBLIC_KEY, my_ltpk_bytes),
            tlv8.Entry(HAP_TLV_TAGS.SIGNATURE, info_sig),
        ])
        encData = self.aeadCtx.encrypt(b'\0\0\0\0PS-Msg05', inner_payload, b'')

        payload = tlv8.encode([
            tlv8.Entry(HAP_TLV_TAGS.STATE, 5),
            tlv8.Entry(HAP_TLV_TAGS.ENCRYPTED_DATA, encData),
        ])
        #print('M5 request payload: %s' % (payload.hex(),))
        print('M5 ->')
        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response
        #print('M6 response CoAP(code:%s) payload: %s' % (response.code, response.payload.hex()))
        print('<- M6')

        # pair-setup M6
        m6 = decode_tlv(response.payload)
        #print('M6 %r' % (m4,))

        if HAP_TLV_TAGS.ERROR_CODE in m6:
            print('Error! Code=%d' % (m6[HAP_TLV_TAGS.ERROR_CODE].data,))
            return None

        if HAP_TLV_TAGS.STATE not in m6 or m6[HAP_TLV_TAGS.STATE].data != 6:
            print('Error! Bad sequence.')
            return None

        if HAP_TLV_TAGS.ENCRYPTED_DATA not in m6:
            print('Error! Missing M4 parameters.')
            return None

        encData = bytes(m6[HAP_TLV_TAGS.ENCRYPTED_DATA].data)
        decData = self.aeadCtx.decrypt(b'\0\0\0\0PS-Msg06', encData, b'')
        decTlv = decode_tlv(decData)

        dev_uuid = bytes(decTlv[HAP_TLV_TAGS.IDENTIFIER].data)
        dev_ltpk = bytes(decTlv[HAP_TLV_TAGS.PUBLIC_KEY].data)
        dev_sig = bytes(decTlv[HAP_TLV_TAGS.SIGNATURE].data)

        expanded_key = self.__derive_key(SrpClient.to_byte_array(session_key), b'Pair-Setup-Accessory-Sign-Salt', b'Pair-Setup-Accessory-Sign-Info')
        dev_info = expanded_key + dev_uuid + dev_ltpk

        Ed25519PublicKey.from_public_bytes(dev_ltpk).verify(dev_sig, dev_info)

        my_ltsk_bytes = my_ltsk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print('OurPairingID(%s) LTSK(%s)' % (my_uuid.hex(), my_ltsk_bytes.hex()))
        print('DevPairingID(%s) LTPK(%s)' % (dev_uuid.hex(), dev_ltpk.hex()))

        print('SUCCESS: pair setup')

        await self.do_pair_verify(dev_ltpk, my_uuid, my_ltsk_bytes)

    async def do_pair_verify(self, dev_ltpk_bytes, my_uuid, my_ltsk_bytes):
        root = resource.Site()
        root.add_resource([], RootResource())
        self.coapClient = await Context.create_server_context(root, bind=('::',0))
        uri = "coap://%s/2" % (self.address)
        print(f"Pair-Verify uri={uri}")

        # pair-verify M1
        ourSK = X25519PrivateKey.generate()
        ourPK = ourSK.public_key()
        ourPKbytes = ourPK.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

        payload = tlv8.encode([
            tlv8.Entry(HAP_TLV_TAGS.STATE, 1),
            tlv8.Entry(HAP_TLV_TAGS.PUBLIC_KEY, ourPKbytes)
        ])
        #print('M1 request payload: %s' % (payload.hex(),))
        print('M1 ->')
        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response
        #print('M2 response CoAP(code:%s) payload: %s' % (response.code, response.payload.hex()))
        print('<- M2')

        # pair-verify M2
        m2 = decode_tlv(response.payload)
        #print('M2 %r' % (m2,))

        if HAP_TLV_TAGS.ERROR_CODE in m2:
            print('Error! Code=%d' % (m2[HAP_TLV_TAGS.ERROR_CODE].data,))

        if HAP_TLV_TAGS.STATE not in m2 or m2[HAP_TLV_TAGS.STATE].data != 2:
            print('Error! Bad sequence.')
            return None

        if HAP_TLV_TAGS.PUBLIC_KEY not in m2 or HAP_TLV_TAGS.ENCRYPTED_DATA not in m2:
            print('Error! Missing M2 parameters.')
            return None

        devPKbytes = bytes(m2[HAP_TLV_TAGS.PUBLIC_KEY].data)
        devPK = X25519PublicKey.from_public_bytes(devPKbytes)
        encData = bytes(m2[HAP_TLV_TAGS.ENCRYPTED_DATA].data)

        shared_secret = ourSK.exchange(devPK)
        session_key = self.__derive_key(shared_secret, b'Pair-Verify-Encrypt-Salt', b'Pair-Verify-Encrypt-Info')
        self.aeadCtx = ChaCha20Poly1305(session_key)

        decData = self.aeadCtx.decrypt(b'\0\0\0\0PV-Msg02', encData, b'')
        decTlv = decode_tlv(decData)

        dev_uuid = bytes(decTlv[HAP_TLV_TAGS.IDENTIFIER].data)
        dev_sig = bytes(decTlv[HAP_TLV_TAGS.SIGNATURE].data)

        # XXX XXX XXX look up dev_ltpk using dev_uuid
        dev_info = devPKbytes + dev_uuid + ourPKbytes

        Ed25519PublicKey.from_public_bytes(dev_ltpk_bytes).verify(dev_sig, dev_info)

        # pair-verify M3
        # XXX XXX XXX look up my_uuid
        my_info = ourPKbytes + my_uuid + devPKbytes

        # XXX XXX XXX look up my_ltsk_bytes
        my_ltsk = Ed25519PrivateKey.from_private_bytes(my_ltsk_bytes)

        info_sig = my_ltsk.sign(my_info)

        inner_payload = tlv8.encode([
            tlv8.Entry(HAP_TLV_TAGS.IDENTIFIER, my_uuid),
            tlv8.Entry(HAP_TLV_TAGS.SIGNATURE, info_sig),
        ])
        encData = self.aeadCtx.encrypt(b'\0\0\0\0PV-Msg03', inner_payload, b'')

        payload = tlv8.encode([
            tlv8.Entry(HAP_TLV_TAGS.STATE, 3),
            tlv8.Entry(HAP_TLV_TAGS.ENCRYPTED_DATA, encData),
        ])

        print('M3 ->')
        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response
        #print('M4 response CoAP(code:%s) payload: %s' % (response.code, response.payload.hex()))
        print('<- M4')

        # pair-verify M4
        m4 = decode_tlv(response.payload)
        #print('M4 %r' % (m4,))

        if HAP_TLV_TAGS.ERROR_CODE in m4:
            print('Error! Code=%d' % (m4[HAP_TLV_TAGS.ERROR_CODE].data,))
            return None

        if HAP_TLV_TAGS.STATE not in m4 or m4[HAP_TLV_TAGS.STATE].data != 4:
            print('Error! Bad sequence.')
            return None

        recvKey = self.__derive_key(shared_secret, b'Control-Salt', b'Control-Read-Encryption-Key')
        recvCtx = ChaCha20Poly1305(recvKey)
        sendKey = self.__derive_key(shared_secret, b'Control-Salt', b'Control-Write-Encryption-Key')
        sendCtx = ChaCha20Poly1305(sendKey)
        eventKey = self.__derive_key(shared_secret, b'Event-Salt', b'Event-Read-Encryption-Key')
        eventCtx = ChaCha20Poly1305(eventKey)
        self.encCtx = my_sessions[request.remote.hostinfo] = EncCtx(recvCtx, sendCtx, eventCtx)

        print('SUCCESS: pair verify')

        await self.get_accessory_info()

    async def do_remove_pairing(self, pairing_id):
        '''
M1 ->
<- M2
M3 ->
<- M4
SUCCESS: pair verify
PDU response, TID 70, Success, Len 1108
M1 request payload: 000299250008000106060101000105
M1 ->
M1 response CoAP(code:2.04 Changed) payload: 0299000000
<- M1
M2 request payload: 00039a25000000
M2 ->
M2 response CoAP(code:2.04 Changed) payload: 029a005000014e060102012464646435313531312d663638322d346433322d396265312d6561643630393665316164660320f842d6de7dcfb448ae79d95735cb7e84a80d7005a5016f36af45
2097f38477a90b0101
<- M2
M2 <EntryList [<tlv8.Entry object at 0x7f62adbd0cd0>]>
[
  <1, [
    <6, 2>,
    <1, b'ddd51511-f682-4d32-9be1-ead6096e1adf'>,
    <3, b'\xf8B\xd6\xde}\xcf\xb4H\xaey\xd9W5\xcb~\x84\xa8\rp\x05\xa5\x01o6\xafE \x97\xf3\x84w\xa9'>,
    <11, 1>,
  ]>,
]
M1 request payload: 00029925002e00012c060101000104012464646435313531312d663638322d346433322d396265312d656164363039366531616466
M1 ->
M1 response CoAP(code:2.04 Changed) payload: 0299000000
<- M1
M2 request payload: 00039a25000000
M2 ->
M2 response CoAP(code:2.04 Changed) payload: 029a0005000103060102
<- M2
M2 <EntryList [<tlv8.Entry object at 0x7f62ad72cbb0>]>
[
  <1, [
    <6, 2>,
  ]>,
]
        '''
        uri = "coap://%s/" % (self.address)

        characteristic = self.services.find_service_characteristic_by_type(0x55, 0x50)

        tlv_payload = tlv8.encode([
            tlv8.Entry(HAP_TLV_TAGS.STATE, 1),
            tlv8.Entry(HAP_TLV_TAGS.METHOD, HAP_PAIRING_METHODS.LIST_PAIRINGS),
        ])
        inner_payload = tlv8.encode([tlv8.Entry(HAP_PDU_TLV_TAGS.HAP_PARAM_VALUE, tlv_payload)])
        payload = self._hap_pdu(HAP_PDU_OPCODES.HAP_CHARACTERISTIC_WRITE, 0x99, characteristic.iid, inner_payload)
        print('M1 request payload: %s' % (payload.hex(),))
        print('M1 ->')
        payload = self.encCtx.encrypt(payload)
        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response
        payload = self.encCtx.decrypt(response.payload)
        print('M1 response CoAP(code:%s) payload: %s' % (response.code, payload.hex()))
        print('<- M1')

        payload = self._hap_pdu(HAP_PDU_OPCODES.HAP_CHARACTERISTIC_READ, 0x9A, characteristic.iid, b'')
        print('M2 request payload: %s' % (payload.hex(),))
        print('M2 ->')
        payload = self.encCtx.encrypt(payload)
        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response
        payload = self.encCtx.decrypt(response.payload)
        print('M2 response CoAP(code:%s) payload: %s' % (response.code, payload.hex()))
        print('<- M2')

        # list pairings M2
        m2 = decode_list_pairings_response(payload[5:])
        print('M2 %r' % (m2,))
        #for k in m2.keys():
        #    print('- %r = %s' % (k, bytes(m2[k].data).hex()))
        print(tlv8.format_string(m2))

        # XXX XXX XXX
        tlv_payload = tlv8.encode([
            tlv8.Entry(HAP_TLV_TAGS.STATE, 1),
            tlv8.Entry(HAP_TLV_TAGS.METHOD, HAP_PAIRING_METHODS.REMOVE_PAIRING),
            tlv8.Entry(HAP_TLV_TAGS.IDENTIFIER, pairing_id),
        ])
        inner_payload = tlv8.encode([tlv8.Entry(HAP_PDU_TLV_TAGS.HAP_PARAM_VALUE, tlv_payload)])
        payload = self._hap_pdu(HAP_PDU_OPCODES.HAP_CHARACTERISTIC_WRITE, 0x99, characteristic.iid, inner_payload)
        print('M1 request payload: %s' % (payload.hex(),))
        print('M1 ->')
        payload = self.encCtx.encrypt(payload)
        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response
        payload = self.encCtx.decrypt(response.payload)
        print('M1 response CoAP(code:%s) payload: %s' % (response.code, payload.hex()))
        print('<- M1')

        payload = self._hap_pdu(HAP_PDU_OPCODES.HAP_CHARACTERISTIC_READ, 0x9A, characteristic.iid, b'')
        print('M2 request payload: %s' % (payload.hex(),))
        print('M2 ->')
        payload = self.encCtx.encrypt(payload)
        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response
        payload = self.encCtx.decrypt(response.payload)
        print('M2 response CoAP(code:%s) payload: %s' % (response.code, payload.hex()))
        print('<- M2')

        # XXX remove pairings M2
        m2 = decode_list_pairings_response(payload[5:])
        print('M2 %r' % (m2,))
        #for k in m2.keys():
        #    print('- %r = %s' % (k, bytes(m2[k].data).hex()))
        print(tlv8.format_string(m2))

    async def get_accessory_info(self):
        uri = "coap://%s/" % (self.address)
        buf = bytearray(7)
        #                                  Control     Op    TID   IID     Len
        struct.pack_into('<BBBHH', buf, 0, 0b00000000, 0x09, 0x70, 0x0000, 0x0000)
        payload = self.encCtx.encrypt(bytes(buf))

        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response

        payload = self.encCtx.decrypt(response.payload)

        pduControl, pduTid, pduStatus, pduBodyLen = struct.unpack('<BBBH', payload[0:5])
        print('PDU %s, TID %02x, %s, Len %d' % (pduControl & 0b00001110 == 0b00000010 and 'response' or 'request', pduTid, pduStatusMap[pduStatus], pduBodyLen))

        pduBody = payload[5:]

        tlv = decode_pdu_09(pduBody)
        services_tlv = tlv.first_by_id(HAP_PDU_TLV_TAGS.UNK_18).data.first_by_id(HAP_PDU_TLV_TAGS.UNK_19).data.first_by_id(HAP_PDU_TLV_TAGS.UNK_16_SERVICES).data
        self.services = PduAccessoryInfo(1, services_tlv)

    async def dump_accessory_info(self):
        if not self.services:
            await self.get_accessory_info()
        print('%r' % (self.services,))

    def _hap_pdu(self, opcode, tid, iid, data):
        buf = bytearray(7)
        struct.pack_into('<BBBHH', buf, 0, 0b00000000, opcode, tid, iid, len(data))
        return bytes(buf + data)

    async def subscribe_to(self, service_type, characteristic_type):
        uri = "coap://%s/" % (self.address)
        buf = bytearray(7)

        characteristic = self.services.find_service_characteristic_by_type(service_type, characteristic_type)
        if not characteristic:
            print('Error! Service/Characteristic not found.')
            return
        if not characteristic.properties.notifies_events_in_connected_state:
            print('Error! Characteristic cannot be subscribed to.')
            return

        struct.pack_into('<BBBHH', buf, 0, 0b00000000, HAP_PDU_OPCODES.UNK_0B_SUBSCRIBE, 0x70, characteristic.iid, 0x0000)
        payload = self.encCtx.encrypt(bytes(buf))

        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response

        payload = self.encCtx.decrypt(response.payload)

        pduControl, pduTid, pduStatus, pduBodyLen = struct.unpack('<BBBH', payload[0:5])
        print('PDU %s, TID %02x, %s, Len %d' % (pduControl & 0b00001110 == 0b00000010 and 'response' or 'request', pduTid, pduStatusMap[pduStatus], pduBodyLen))

    async def read_all_characteristics(self):
        uri = "coap://%s/" % (self.address)

        hkaccy = Accessory()
        for service in self.services.services:
            readable_characteristics = [characteristic for characteristic in service.characteristics if characteristic.properties.supports_secure_reads]
            read_all = b''.join([self._hap_pdu(HAP_PDU_OPCODES.HAP_CHARACTERISTIC_READ, idx, characteristic.iid, b'') for (idx, characteristic) in enumerate(readable_characteristics)])
            payload = self.encCtx.encrypt(read_all)

            request = Message(code=POST, payload=payload, uri=uri)
            response = await self.coapClient.request(request).response

            payload = self.encCtx.decrypt(response.payload)

            offset = 0
            results = []
            while True:
                pduControl, pduTid, pduStatus, pduBodyLen = struct.unpack('<BBBH', payload[offset : offset + 5])
                #print('PDU %s, TID %02x, %s, Len %d' % (pduControl & 0b00001110 == 0b00000010 and 'response' or 'request', pduTid, pduStatusMap[pduStatus], pduBodyLen))

                if pduBodyLen > 0:
                    results.append(decode_pdu_03(payload[offset + 5 : offset + 5 + pduBodyLen]))
                else:
                    results.append(b'')

                offset += (5 + pduBodyLen)
                if offset >= len(payload):
                    break

            hkserv = Service(hkaccy, '%X' % (service.service_type,))
            print('Service(%s)' % (hkserv.type,))
            for idx, c in enumerate(readable_characteristics):
                hkc = Characteristic(hkserv, '%X' % (c.type,), **c.to_dict())
                txt = ''
                if not c.pf_format:
                    txt = '(hex) ' + results[idx].hex()
                elif c.pf_format == 0x01:
                    txt = '(bool) %s' % struct.unpack('<?', results[idx])
                elif c.pf_format == 0x04:
                    txt = '(uint8) %d' % struct.unpack('<B', results[idx])
                elif c.pf_format == 0x06:
                    txt = '(uint16) %d' % struct.unpack('<H', results[idx])
                elif c.pf_format == 0x08:
                    txt = '(uint32) %d' % struct.unpack('<L', results[idx])
                elif c.pf_format == 0x0A:
                    txt = '(uint64) %d' % struct.unpack('<Q', results[idx])
                elif c.pf_format == 0x10:
                    txt = '(int32) %d' % struct.unpack('<l', results[idx])
                elif c.pf_format == 0x14:
                    txt = '(float) %f' % struct.unpack('<f', results[idx])
                elif c.pf_format == 0x19:
                    txt = '(str) ' + bytes.decode(results[idx])
                elif c.pf_format == 0x1B:
                    txt = '(data) ' + results[idx].hex()
                else:
                    txt = '(unk/%02x) ' % (c.pf_format,) + results[idx].hex()
                print('  Characteristic(%s)=%s' % (hkc.type, txt))

    async def read_characteristic(self, service_type, characteristic_type):
        uri = "coap://%s/" % (self.address)
        buf = bytearray(7)

        characteristic = self.services.find_service_characteristic_by_type(service_type, characteristic_type)
        if not characteristic:
            print('Error! Service/Characteristic not found.')
            return
        if not characteristic.properties.supports_secure_reads:
            print('Error! Characteristic cannot be read.')
            return

        struct.pack_into('<BBBHH', buf, 0, 0b00000000, HAP_PDU_OPCODES.HAP_CHARACTERISTIC_READ, 0x70, characteristic.iid, 0x0000)
        payload = self.encCtx.encrypt(bytes(buf))

        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response

        payload = self.encCtx.decrypt(response.payload)

        pduControl, pduTid, pduStatus, pduBodyLen = struct.unpack('<BBBH', payload[0:5])
        print('PDU %s, TID %02x, %s, Len %d' % (pduControl & 0b00001110 == 0b00000010 and 'response' or 'request', pduTid, pduStatusMap[pduStatus], pduBodyLen))

        print(f"Read data={payload[5:].hex()}")
        decoded = decode_pdu_03(payload[5:])
        print('Body: %s' % (decoded.hex(),))

    async def write_characteristic(self, service_type, characteristic_type, value):
        uri = "coap://%s/" % (self.address)
        buf = bytearray(7)

        characteristic = self.services.find_service_characteristic_by_type(service_type, characteristic_type)
        if not characteristic:
            print('Error! Service/Characteristic not found.')
            return
        if not characteristic.properties.supports_secure_writes:
            print('Error! Characteristic cannot be written.')
            return

        inner_payload = tlv8.encode([tlv8.Entry(HAP_PDU_TLV_TAGS.HAP_PARAM_VALUE, value)])
        struct.pack_into('<BBBHH', buf, 0, 0b00000000, HAP_PDU_OPCODES.HAP_CHARACTERISTIC_WRITE, 0x70, characteristic.iid, len(inner_payload))
        payload = self.encCtx.encrypt(bytes(buf) + inner_payload)

        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response

        payload = self.encCtx.decrypt(response.payload)

        pduControl, pduTid, pduStatus, pduBodyLen = struct.unpack('<BBBH', payload[0:5])
        print('PDU %s, TID %02x, %s, Len %d' % (pduControl & 0b00001110 == 0b00000010 and 'response' or 'request', pduTid, pduStatusMap[pduStatus], pduBodyLen))

        print('Body: %s' % (payload[5:].hex(),))

    async def write_pdu(self, service_type, characteristic_type, inner_payload):
        uri = "coap://%s/" % (self.address)
        buf = bytearray(7)

        characteristic = self.services.find_service_characteristic_by_type(service_type, characteristic_type)
        if not characteristic:
            print('Error! Service/Characteristic not found.')
            return
        if not characteristic.properties.supports_secure_writes:
            print('Error! Characteristic cannot be written.')
            return

        struct.pack_into('<BBBHH', buf, 0, 0b00000000, HAP_PDU_OPCODES.HAP_CHARACTERISTIC_WRITE, 0x70, characteristic.iid, len(inner_payload))
        payload = self.encCtx.encrypt(bytes(buf) + inner_payload)

        request = Message(code=POST, payload=payload, uri=uri)
        response = await self.coapClient.request(request).response

        payload = self.encCtx.decrypt(response.payload)

        pduControl, pduTid, pduStatus, pduBodyLen = struct.unpack('<BBBH', payload[0:5])
        print('PDU %s, TID %02x, %s, Len %d' % (pduControl & 0b00001110 == 0b00000010 and 'response' or 'request', pduTid, pduStatusMap[pduStatus], pduBodyLen))

        print('Body: %s' % (payload[5:].hex(),))
        if len(payload[5:]) > 0:
            tlvs = tlv8.deep_decode(payload[5:])
            print(tlv8.format_string(tlvs))

async def get_service_info(zeroconf: Zeroconf, service_type: str, name: str) -> None:
    #info = zeroconf.get_service_info(service_type, name)
    info = AsyncServiceInfo(service_type, name)
    await info.async_request(zeroconf, 3000)
    #print("Info: %r" % (info))
    if info:
        # assuming IPv6 & adding brackets
        addresses = ["[%s]:%d" % (addr, cast(int, info.port)) for addr in info.parsed_addresses()]
        #print("  Addresses: %s" % ", ".join(addresses))

        # add short ID to properties
        print(info.server.split('.'))

        hap_services[addresses[0]] = info.properties

def on_service_state_change(zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
    #print("Service %s of type %s state changed: %s" % (name, service_type, state_change))

    if state_change is ServiceStateChange.Added:
        asyncio.ensure_future(get_service_info(zeroconf, service_type, name))

hap_services = dict()
async def amain(args):
    # discover hap/udp services
    zeroconf = AsyncZeroconf(ip_version=IPVersion.V6Only)
    browser = AsyncServiceBrowser(zeroconf.zeroconf, ["_hap._udp.local."], handlers=[on_service_state_change])
    # ... only wait specified time for devices to respond
    await asyncio.sleep(args.zeroconf_timeout)
    await browser.async_cancel()
    await zeroconf.async_close()
    # ... set up sessions with requested devices
    devices_by_eui64 = dict()
    for addr, properties in hap_services.items():
        # global device filter
        if args.devices and len(args.devices) > 0:
            eui64 = properties.get(b'id').decode('ascii')
            if eui64 not in args.devices:
                continue
        device = HAPThreadDevice(addr, properties)
        devices_by_eui64[eui64] = device
    # ... and then run our actions
    for action in args.action:
        params = []
        targets = devices_by_eui64.values()

        if '=' in action:
            action, tmp = action.split('=')
            params = tmp.split(',')
        if '@' in action:
            # action-specific device filter
            action, devid = action.split('@')
            target = devices_by_eui64.get(devid)
            targets = [target] if target else []
        if len(targets) == 0:
            print("No matching devices for action %s@%s" % (action, devid))
            continue

        #print('action=%s, params=%r, targets=%r' % (action, params, targets))
        if action == 'auth' and len(params) > 0:
            if len(params[0]) == 10:
                [await target.do_pair_setup(params[0]) for target in targets]
            else:
                [await target.do_pair_verify(
                    bytes.fromhex(params[0]),
                    bytes(params[1], encoding='ascii'),
                    bytes.fromhex(params[2])
                ) for target in targets]
        elif action == 'dump':
            [await target.dump_accessory_info() for target in targets]
        elif action == 'pair':
            [await target.do_pair_setup(params[0]) for target in targets]
        elif action == 'pause':
            await asyncio.sleep(int(params[0]))
        elif action == 'read':
            [await target.read_characteristic(int(params[0], base=16), int(params[1], base=16)) for target in targets]
        elif action == 'readall':
            [await target.read_all_characteristics() for target in targets]
        elif action == 'subscribe':
            [await target.subscribe_to(int(params[0], base=16), int(params[1], base=16)) for target in targets]
        elif action == 'unpair':
            [await target.do_remove_pairing(bytes(params[0], encoding='ascii')) for target in targets]
        elif action == 'write':
            [await target.write_characteristic(int(params[0], base=16), int(params[1], base=16), bytes.fromhex(params[2])) for target in targets]
        elif action == 'writepdu':
            [await target.write_pdu(int(params[0], base=16), int(params[1], base=16), bytes.fromhex(params[2])) for target in targets]

    if args.wait:
        await asyncio.get_running_loop().create_future()

### MAIN ###
logging.basicConfig(level=logging.INFO)
#logging.getLogger('zeroconf').setLevel(logging.DEBUG)

parser = argparse.ArgumentParser()
parser.add_argument('action', help='actions to perform (auth[@ID]=pin/token; color=h,s,v; identify; pause=seconds; power=on/off; state)', nargs='+')
parser.add_argument('--devices', help='list of device IDs to perform actions on', type=lambda x: x.split(','))
parser.add_argument('--wait', help='wait forever, useful to receive subscription notifications', action='store_true')
parser.add_argument('--zeroconf-timeout', help='seconds to wait for device discovery', type=int, default=2)
args = parser.parse_args()

asyncio.get_event_loop().run_until_complete(amain(args))

### EXAMPLES ###
## pair with accessory
# hapcoap.py --devices 1234 pair=123-45-678
## to perform any other action you need:
# - the device long-term public key
# - our pairing ID
# - our long-term secret key
## these hex values are output after the pair process
# hapcoap.py --devices 1234 auth=AccessoryLTPK,OurPairingID,OurLTSK ...
## subscribe to a Light accessory's On characteristic
# hapcoap.py --wait --devices 1234 auth=LTPK,OurPairingID,LTSK subscribe=43,25
## read a Light accessory's Name, On, ColorTemp, Brightness, Hue, Saturation
# hapcoap.py --devices 1234 auth=... read=43,23 read=43,25 read=43,CE read=43,08 read=43,13 read=43,2F
## toggle a light off and on
# hapcoap.py --devices 1234 auth=... write=43,25,00 pause=3 write=43,25,01
