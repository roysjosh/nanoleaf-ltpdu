import tlv8

GATT = bytes.fromhex('''
18ff19ff1a02010016ff15f10702010006013e100014e61314\
050202000401140a0220000c070100002701000000001314050203000401\
200a0210000c071900002701000000001314050204000401210a0210000c\
071900002701000000001314050205000401230a0210000c071900002701\
000000001314050206000401300a0210000c071900002701000000001314\
050207000401520a0210000c071900002701000000001314050208000401\
530a0210000c0719000027010000000013230502090004103b94f9856afd\
c3ba40437fac1188ab340a0250000c07190000270100000000131505020a\
00040220020a0250000c071b0000270100000000153d18ff070219ff1000\
0601a20f16ff0204001000142e1314050211000401a50a0210000c071b00\
002701000000001314050212000401370a0210000c071900002701000000\
001569070220000601551000145e13140502220004014c0a0203000c071b\
000027010000000013140502230004014e0a0203000c071b000027010000\
000013140502240004014f0a0201000c0704000027010000000013140502\
25000401500a0230000c071b000027010000000015ff070230000601430f\
020100100014ff1314050231000401a50a0210000c071b00002701000000\
001314050232000401230a0210000c071900002701000000001314050233\
000401250a02b0030c18ff0701000019ff270100000000131e16ff050237\
000401ce0a02b0030c07080000270100000d0899000000d6010000000013\
1e050234000401080a02b0030c071000ad270100000d0800000000640000\
000000132305023c000410bdeeeece71000fa1374da1cf02198ea20a0270\
000c071b0000270100000000131505023900040244010a0210000c071b00\
00270100000000131505023800040243010a0230000c071b000027010000\
0000131905023a0004024b020a15620290030c07040000270100000d0200\
14510200001324050235000401130a02b0030c07140063270100000d0800\
0000000000b4430e040000803f000013240502360004012f0a0218ffb003\
0c07140019ffad270100000d0800000016ff000000c8420e040000803f00\
0015ab07027000060201071000149f1314050271000401a50a0210000c07\
1b0000270100000000131505027400040206070a0210000c071900002701\
00000000131b05027300040202070a0210000c07060000270100000d0400\
001f000000131b05027500040203070a0290030c07060000270100000d04\
00007f00000013150502760004022b020a0210000c070100002701000000\
00131505027700040204070a0230000c071b000027010000000015770702\
000a060239021000146b13140502040a0401a50a0210000c071b00002701\
00000000131f0502010a04023a184e020a0210000c070819440000270100\
000d08000000001636ffffff03000013150502020a04023c020a0211000c\
071b000027010000000013150502050a04024a020a0290030c0708000027\
010000''')

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

class PduCharacteristicProperties():
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
        return '{"r":%s,"w":%s,"aad":%s,"tw":%s,"sr":%s,"sw":%s,"hidden":%s,"evc":%s,"evd":%s,"bcast":%s}' % (
            self.supports_read and 'true' or 'false',
            self.supports_write and 'true' or 'false',
            self.supports_additional_authorization_data and 'true' or 'false',
            self.requires_hap_characteristic_timed_write_procedure and 'true' or 'false',
            self.supports_secure_reads and 'true' or 'false',
            self.supports_secure_writes and 'true' or 'false',
            self.hidden_from_user and 'true' or 'false',
            self.notifies_events_in_connected_state and 'true' or 'false',
            self.notifies_events_in_disconnected_state and 'true' or 'false',
            self.supports_broadcast_notify and 'true' or 'false'
        )

class PduCharacteristic():
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

    def __repr__(self):
        return '{"type":"UUID(%x)","instance_id":"%s","properties":%s}' % (
            self.type and self.type or '',
            self.iid and '0x%04x' % (self.iid,) or '',
            repr(self.properties)
        )

class PduService():
    def __init__(self, service_tlv):
        self.service_type = service_tlv.first_by_id(HAP_PDU_TLV_TAGS.HAP_PARAM_SERVICE_TYPE)
        if self.service_type:
            self.service_type = int.from_bytes(self.service_type.data, 'little')

        self.service_instance_id = service_tlv.first_by_id(HAP_PDU_TLV_TAGS.HAP_PARAM_SERVICE_INSTANCE_ID)
        if self.service_instance_id:
            self.service_instance_id = self.service_instance_id.data

        self.characteristics = [PduCharacteristic(characteristic_tlv.data) for characteristic_tlv in service_tlv.first_by_id(HAP_PDU_TLV_TAGS.UNK_14_CHARACTERISTICS).data.by_id(HAP_PDU_TLV_TAGS.UNK_13_CHARACTERISTIC)]

    def __repr__(self):
        return '{"type":"UUID(%x)","iid":"%s","characteristics":%s}' % (
            self.service_type and self.service_type or '',
            self.service_instance_id and '0x%04x' % (self.service_instance_id,) or '',
            repr(self.characteristics)
        )

    def find_characteristic_by_type(self, characteristic_type):
        for characteristic in self.characteristics:
            if characteristic.type == characteristic_type:
                return characteristic
        return None

class PduServices():
    def __init__(self, services_tlv):
        self.services = [PduService(service_tlv.data) for service_tlv in services_tlv.by_id(HAP_PDU_TLV_TAGS.UNK_15_SERVICE)]

    def __repr__(self):
        return '{"services":' + repr(self.services) + '}'

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

tlv = decode_pdu_09(GATT)
services_tlv = tlv.first_by_id(HAP_PDU_TLV_TAGS.UNK_18).data.first_by_id(HAP_PDU_TLV_TAGS.UNK_19).data.first_by_id(HAP_PDU_TLV_TAGS.UNK_16_SERVICES).data

services = PduServices(services_tlv)
print('%r' % (services,))

#light_on = services.find_service_characteristic_by_type(0x43, 0x25)
#print('Light On IID=0x%04x ... %r' % (light_on.iid, light_on,))

# get IID of service/characteristic
# python3 gatt.py | jq -r '.services[] | select(.type == "UUID(43)") | .characteristics[] | select(.type == "UUID(25)") | .instance_id'

# get all characteristics that support events
# python3 gatt.py | jq -r '.services[].characteristics[] | select(.properties.evc == true) | .instance_id'
