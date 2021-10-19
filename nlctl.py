import argparse
import asyncio
import logging
import struct
import sys

from aiocoap import *
from cryptography.hazmat.primitives import ciphers, hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from typing import cast
from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf, AsyncZeroconfServiceTypes

def create_tlv(typ, data):
    buf = bytearray(2 + 2)
    struct.pack_into("!HH", buf, 0, typ, len(data))
    return buf + data

class NanoleafEssentials:
    def __init__(self, address, properties):
        self.address = address
        self.properties = properties
        self.aesCtx = None
        self.coapClient = None

    async def __do_kex(self):
        self.coapClient = await Context.create_client_context()
        uri = "coap://%s/nlsecure" % (self.address)

        ourSK = X25519PrivateKey.generate()
        ourPK = ourSK.public_key()
        #print("Our secret key: %r" % (ourSK))
        #print("Our public key: %r" % (ourPK))
        ourPKbytes = ourPK.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

        payload = create_tlv(0x0101, ourPKbytes)
        #print("Payload: %r" % (payload))
        request = Message(code=POST, payload=payload, uri=uri)

        response = await self.coapClient.request(request).response
        print("KEX response CoAP(code:%s) header: %s" % (response.code, response.payload[0:4].hex()))
        # XXX check for type/len in payload
        devPK = X25519PublicKey.from_public_bytes(response.payload[4:])
        shared_secret = ourSK.exchange(devPK)
        #print("Shared secret: %s" % (shared_secret.hex()))

        # generate key/iv
        digest = hashes.Hash(hashes.SHA1())
        digest.update(bytearray(b'AES-NL-OPENAPI-KEY') + shared_secret)
        aesKey = digest.finalize()[0:16]
        #print("AES key: %s" % (aesKey.hex()))

        digest = hashes.Hash(hashes.SHA1())
        digest.update(bytearray(b'AES-NL-OPENAPI-IV') + shared_secret)
        aesIv = digest.finalize()[0:16]
        #print("AES IV: %s" % (aesIv.hex()))

        aesCipher = ciphers.Cipher(ciphers.algorithms.AES(aesKey), ciphers.modes.CTR(aesIv))
        self.aesCtx = aesCipher.encryptor()

    async def get_access_token(self, pin):
        if not self.aesCtx:
            await self.__do_kex()

        uri = "coap://%s/nlsecure" % (self.address)

        payload = self.aesCtx.update(create_tlv(0x0103, pin))
        request = Message(code=POST, payload=payload, uri=uri)

        response = await self.coapClient.request(request).response
        # XXX check for plaintext error
        print("Auth/PIN response CoAP(code:%s) header: %s payload: %s" % (response.code, response.payload[0:4].hex(), response.payload[4:].hex()))
        mystery = self.aesCtx.update(response.payload)
        # XXX check for ciphertext error
        print("Access token: %s" % (mystery.hex()))

    async def auth_with_access_token(self, access_token):
        if not self.aesCtx:
            await self.__do_kex()

        uri = "coap://%s/nlsecure" % (self.address)

        payload = self.aesCtx.update(create_tlv(0x0104, access_token))
        request = Message(code=POST, payload=payload, uri=uri)

        response = await self.coapClient.request(request).response
        # XXX check for plaintext error
        print("Auth/Token response CoAP(code:%s) header: %s payload: %s" % (response.code, response.payload[0:4].hex(), response.payload[4:].hex()))
        mystery = self.aesCtx.update(response.payload)
        # XXX check for ciphertext error
        print("Auth/Token plaintext: %s" % (mystery.hex()))

    async def disconnect(self):
        uri = "coap://%s/nlsecure" % (self.address)

        payload = self.aesCtx.update(create_tlv(0x0105, b''))
        request = Message(code=POST, payload=payload, uri=uri)

        response = await self.coapClient.request(request).response
        print("Disconnect response CoAP(code:%s) header: %s payload: %s" % (response.code, response.payload[0:4].hex(), response.payload[4:].hex()))
        plaintext = self.aesCtx.update(response.payload)
        print("Disconnect plaintext: %s" % (plaintext.hex()))

        self.aesCtx = None

    async def turn_light_color(self, hue, sat, val):
        uri = "coap://%s/nlltpdu" % (self.address)

        payload = self.aesCtx.update(
            # make sure the light is on
            create_tlv(0x0001, b'lb/0/oo') + create_tlv(0x0002, b'\x01')
            + create_tlv(0x0001, b'lb/0/hu') + create_tlv(0x0002, hue.to_bytes(2, byteorder='big'))
            + create_tlv(0x0001, b'lb/0/sa') + create_tlv(0x0002, sat.to_bytes(2, byteorder='big'))
            + create_tlv(0x0001, b'lb/0/pb') + create_tlv(0x0002, val.to_bytes(2, byteorder='big'))
        )
        request = Message(code=POST, payload=payload, uri=uri)

        response = await self.coapClient.request(request).response
        # XXX check for ciphertext error
        print("Execute TurnLightColor response CoAP(code:%s) header: %s payload: %s" % (response.code, response.payload[0:4].hex(), response.payload[4:].hex()))
        rbuf = self.aesCtx.update(response.payload)
        # XXX check for plaintext error
        print("Execute TurnLightColor plaintext: %s" % (rbuf.hex()))

    async def turn_light_on_off(self, on_off):
        uri = "coap://%s/nlltpdu" % (self.address)

        payload = self.aesCtx.update(create_tlv(0x0001, b'lb/0/oo') + create_tlv(0x0002, on_off))
        request = Message(code=POST, payload=payload, uri=uri)

        response = await self.coapClient.request(request).response
        # XXX check for ciphertext error
        print("Execute LightOnOff response CoAP(code:%s) header: %s payload: %s" % (response.code, response.payload[0:4].hex(), response.payload[4:].hex()))
        rbuf = self.aesCtx.update(response.payload)
        # XXX check for plaintext error
        print("Execute LightOnOff plaintext: %s" % (rbuf.hex()))

    async def identify(self):
        uri = "coap://%s/nlpublic" % (self.address)

        payload = create_tlv(0x0001, b'lb/0/id') + create_tlv(0x0002, b'')
        request = Message(code=POST, payload=payload, uri=uri)

        response = await self.coapClient.request(request).response
        print("Execute Identify response CoAP(code:%s) header: %s payload: %s" % (response.code, response.payload[0:4].hex(), response.payload[4:].hex()))

    async def get_device_info(self):
        uri = "coap://%s/nlltpdu" % (self.address)

        payload = self.aesCtx.update(
            create_tlv(0x0001, b'di') + create_tlv(0x0002, b'')
            + create_tlv(0x0001, b'lb/0/oo') + create_tlv(0x0002, b'')
            + create_tlv(0x0001, b'lb/0/pb') + create_tlv(0x0002, b'')
            + create_tlv(0x0001, b'lb/0/hu') + create_tlv(0x0002, b'')
            + create_tlv(0x0001, b'lb/0/sa') + create_tlv(0x0002, b'')
            + create_tlv(0x0001, b'lb/0/ct') + create_tlv(0x0002, b'')
        )
        request = Message(code=GET, payload=payload, uri=uri)

        response = await self.coapClient.request(request).response
        # XXX check for ciphertext error
        print("Query DeviceInfo response CoAP(code:%s) header: %s payload: %s" % (response.code, response.payload[0:4].hex(), response.payload[4:].hex()))
        rbuf = self.aesCtx.update(response.payload)
        # XXX check for plaintext error
        print("Query DeviceInfo plaintext: %s" % (rbuf.hex()))

        # endpoint TLV: 0001 0002 "di"
        # payload TLV: 0003 0026 00 hwver[10] fwver[8] serial[11] eui64[8]
        rtype, rlen = struct.unpack("!HH", rbuf[0:4])
        #print("rtype(%d) rlen(%d) path(%s)" % (rtype, rlen, rbuf[4:4+rlen]))
        if rtype != 0x0001 or rlen != 2 or rbuf[4:6] != b'di':
            print("Invalid DeviceInfo response header")
            #raise "Invalid DeviceInfo response header"
        # XXX also extract status code below
        rtype, rlen = struct.unpack("!HH", rbuf[6:10])
        #print("rtype(%d) rlen(%d)" % (rtype, rlen))
        #if rtype != 0x0003 or rlen != 0x26:
        #    raise "Invalid DeviceInfo response payload type"
        hwver, fwver, serial, eui64 = struct.unpack("!10s8s11sQ", rbuf[11:11+rlen-1])
        print("DeviceInfo hwver(%s) fwver(%s) serial(%s) eui64(%X)" % (hwver, fwver, serial, eui64))

        # lb/0/oo response
        # 0001 0007 6c622f302f6f6f 0003 0002 00 00
        power = rbuf[64]

        # lb/0/pb response
        # 0001 0007 6c622f302f7062 0003 0003 00 0023
        val = int.from_bytes(rbuf[81:83], byteorder='big')

        # lb/0/hu response
        # 0001 0007 6c622f302f6875 0003 0003 00 00d5
        hue = int.from_bytes(rbuf[99:101], byteorder='big')

        # lb/0/sa response
        # 0001 0007 6c622f302f7361 0003 0003 00 003e
        sat = int.from_bytes(rbuf[117:119], byteorder='big')

        # lb/0/ct response
        # 0001 0007 6c622f302f6374 0003 0003 00 1987
        cct = int.from_bytes(rbuf[135:137], byteorder='big')

        return {
            "hwver": hwver.decode('ascii').rstrip('\x00'),
            "fwver": fwver.decode('ascii').rstrip('\x00'),
            "serial": serial.decode('ascii'),
            "eui64": "%X" % (eui64),
            "power": power,
            "val": val,
            "hue": hue,
            "sat": sat,
            "cct": cct,
        }

async def get_service_info(zeroconf: Zeroconf, service_type: str, name: str) -> None:
    #info = zeroconf.get_service_info(service_type, name)
    info = AsyncServiceInfo(service_type, name)
    await info.async_request(zeroconf, 3000)
    #print("Info: %r" % (info))
    if info and info.server.startswith('Nanoleaf-'):
        # assuming IPv6 & adding brackets
        addresses = ["[%s]:%d" % (addr, cast(int, info.port)) for addr in info.parsed_addresses()]
        #print("  Addresses: %s" % ", ".join(addresses))

        # add short ID to properties
        info.properties[b'__id4'] = info.server.split('.')[0].split('-')[2]

        ltpdu_services[addresses[0]] = info.properties

def on_service_state_change(zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
    #print("Service %s of type %s state changed: %s" % (name, service_type, state_change))

    if state_change is ServiceStateChange.Added:
        asyncio.ensure_future(get_service_info(zeroconf, service_type, name))

ltpdu_services = dict()
async def amain(args):
    # discover ltpdu services
    zeroconf = AsyncZeroconf(ip_version=IPVersion.V6Only)
    browser = AsyncServiceBrowser(zeroconf.zeroconf, ["_ltpdu._udp.local."], handlers=[on_service_state_change])
    # ... only wait specified time for devices to respond
    await asyncio.sleep(args.zeroconf_timeout)
    await browser.async_cancel()
    await zeroconf.async_close()
    # ... set up sessions with requested devices
    devices_by_eui64 = dict()
    devices_by_id4 = dict()
    for addr, properties in ltpdu_services.items():
        # global device filter
        if args.devices and len(args.devices) > 0:
            eui64 = properties.get(b'eui64')
            id4 = properties.get(b'__id4')
            if eui64 not in args.devices and id4 not in args.devices:
                continue
        device = NanoleafEssentials(addr, properties)
        devices_by_eui64[properties.get(b'eui64')] = device
        devices_by_id4[properties.get(b'__id4')] = device
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
            target = devices_by_eui64.get(devid, devices_by_id4.get(devid))
            targets = [target] if target else []
        if len(targets) == 0:
            print("No matching devices for action %s@%s" % (action, devid))
            continue

        #print('action=%s, params=%r, targets=%r' % (action, params, targets))
        if action == 'auth' and len(params) > 0:
            if len(params[0]) == 8:
                [await target.get_access_token(params[0]) for target in targets]
            else:
                [await target.auth_with_access_token(bytes.fromhex(params[0])) for target in targets]
        elif action == 'color':
            [await target.turn_light_color(int(params[0]), int(params[1]), int(params[2])) for target in targets]
        elif action == 'identify':
            [await target.identify() for target in targets]
        elif action == 'pause':
            await asyncio.sleep(int(params[0]))
        elif action == 'power':
            [await target.turn_light_on_off(b'\x01' if params[0] == 'on' else b'\x00') for target in targets]
        elif action == 'state':
            print([await target.get_device_info() for target in targets])
    # ... finally, disconnect
    [await target.disconnect() for target in devices_by_eui64.values()]

### MAIN ###
logging.basicConfig(level=logging.INFO)
#logging.getLogger('zeroconf').setLevel(logging.DEBUG)

parser = argparse.ArgumentParser()
parser.add_argument('action', help='actions to perform (auth[@ID/EUI64]=pin/token; color=h,s,v; identify; pause=seconds; power=on/off; state)', nargs='+')
parser.add_argument('--devices', help='list of device IDs/EUI64s to perform actions on', type=lambda x: x.split(','))
parser.add_argument('--zeroconf-timeout', help='seconds to wait for device discovery', type=int, default=1)
args = parser.parse_args()

asyncio.get_event_loop().run_until_complete(amain(args))

### EXAMPLES ###
## get current state of all (authenticated) devices
# nlctl.py auth@3TH2=XXXXXXXXXXXXXXXX auth@12FA=XXXXXXXXXXXXXXXX state
## toggle one bulb for 15 seconds
# nlctl.py --devices 12FA auth=XXXXXXXXXXXXXXXX color=58,69,89 sleep=15 color=310,99,100
## indicate the alarm is armed
# nlctl.py --devices 3TH2 auth=XXXXXXXXXXXXXXXX color=0,88,100
