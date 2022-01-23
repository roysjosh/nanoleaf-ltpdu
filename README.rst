Documentation for the Nanoleaf Essentials API
=============================================

The Essentials bulb by `nanoleaf <https://nanoleaf.me/>`_ recently gained local control via Thread. Using an Elements device as a Thread Border Router causes Essentials devices to be advertised via a mDNS service ``_hap._udp`` and ``_ltpdu._udp``. Those services reference the standard CoAP port and accessing the `CoRE resource discovery endpoint <https://datatracker.ietf.org/doc/html/rfc6690#section-4>`_ reveals the following::

    </.well-known/core>;
    </nlpublic>;
    </nlltpdu>;
    </nlsecure>;
    </>;
    </2>;
    </1>;
    </0>;

nlpublic endpoint
-----------------
The vendor applications communicate with this endpoint when performing the Identify (bulb flash) function. The packet format is clear and used throughout::

    Request:
    CoAP POST /nlpublic

    Data sent (binary, shown as hex below):
    0001 0007 6c622f302f6964 0002 0000

    Data sent (decoded):
    Tag  Len  Value          Tag  Len  Value
    1    7    "lb/0/id"      2    0    (null)

All numbers are in network byte order. Requests to all endpoints contain pairs of TLVs, the first designating the device's function (``lb/0/id`` in this case), and the second providing any arguments. The CoAP status seems to always be 2.04 and should not be relied on for error checking. The returned tag should instead be checked for the expected value.

nlsecure endpoint
-----------------
This endpoint is used to authenticate to the device, either via 8-digit PIN or a previously obtained access token. A CoAP session must be authenticated by one of these two methods before proceeding to call further APIs.

To begin, a X25519 key exchange is performed::

    CoAP POST /nlsecure
    0101 0020 [public key bytes]

The response is as follows::

    CoAP 2.04 Changed
    0101 0020 [device public key bytes]

This keypair is only used to create symmetric keys immediately following the key exchange and can then be discarded. After obtaining the X25519 shared secret, the key and IV are computed::

    key = SHA1("AES-NL-OPENAPI-KEY" || shared_secret)[0:16]
    iv = SHA1("AES-NL-OPENAPI-IV" || shared_secret)[0:16]

Initialize a 128-bit AES-CTR cipher with the key and IV. All encryption and decryption operations are performed via one context; responses are decrypted using the same context that was used to encrypt the request. Further communication to the device using this CoAP session/context MUST be encrypted and decrypted using this cipher context. It is possible that at some point (after X requests, Y time) the device could invalidate the session. If so, just re-authenticate starting from the X25519 key exchange.

PIN authentication
^^^^^^^^^^^^^^^^^^
The 8-digit PIN printed on the bulb is used the first time communication is established and results in a long-lived access token. PIN authentication is performed as follows::

    CoAP POST /nlsecure
    0103 0008 "12345678"

The PIN digits are passed as ASCII characters (0x30-0x39) not their binary representation (0x00-0x09). A successful response contains the access token::

    CoAP 2.04 Changed
    0104 0008 XXXXXXXX

The response is a 64-bit binary access token and should be securely stored for later use.

Access token authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^
To authenticate a CoAP session using an access token, send the following payload::

    CoAP POST /nlsecure
    0104 0008 XXXXXXXX

The 8-byte data field is identical to the data received in the PIN auth response.

Pseudo-code
^^^^^^^^^^^
See `aiocoap <https://github.com/chrysn/aiocoap>`_ and `cryptography <https://github.com/pyca/cryptography>`_ for useful libraries. Make sure to use the same CoAP client and AES context throughout your code after authenticating with the device!

.. code-block:: python3

    # generate our keys
    ourSK = X25519PrivateKey.generate()
    ourPK = ourSK.public_key()
    ourPKbytes = ourPK.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    # create and send payload
    payload = create_tlv(0x0101, ourPKbytes)
    request = Message(code=POST, payload=payload, uri=uri)
    response = await coapClient.request(request).response

    # get shared secret
    devPK = X25519PublicKey.from_public_bytes(response.payload[4:])
    sharedSecret = ourSK.exchange(devPK)

    # get key/iv
    digest = hashes.Hash(hashes.SHA1())
    digest.update(bytearray(b'AES-NL-OPENAPI-KEY') + sharedSecret)
    aesKey = digest.finalize()[0:16]

    digest = hashes.Hash(hashes.SHA1())
    digest.update(bytearray(b'AES-NL-OPENAPI-IV') + sharedSecret)
    aesIv = digest.finalize()[0:16]

    aesCipher = ciphers.Cipher(ciphers.algorithms.AES(aesKey), ciphers.modes.CTR(aesIv))
    aesCtx = aesCipher.encryptor()

    # all further payloads (sent & received) must be wrapped in aesCtx.update

nlltpdu endpoint
----------------
Queries to this endpoint follow the format of the nlpublic endpoint. Multiple queries can be concatenated in a single request payload; responses are returned concatenated in the same order as the request. The entire payload must be encrypted with the context created above. The received payload is decrypted with the same context. Do not send a request while you are waiting for a response until a timeout has passed! This will desynchronize your cipher context due to the decision to share the enc/dec context. Make use of multiple requests in a payload instead.

==========  ========  ======
Function    Endpoint  Length
==========  ========  ======
DeviceInfo  di        36
On/Off      lb/0/oo   1
Brightness  lb/0/pb   2
Hue         lb/0/hu   2
Saturation  lb/0/sa   2
CCT (temp)  lb/0/ct   2
==========  ========  ======

Color appears to be HSV (hue, saturation, value) versus HSL (hue, saturation, lightness).

Requests for information use GET::

    CoAP GET /nlltpdu
    0001 LLLL ENDPOINT 0002 0000

Responses typically have their second TLV as type 0003 which contains a status code after the length but before the payload::

    CoAP 2.04 Changed
    0001 LLLL ENDPOINT 0003 LLLL SC XX[len-1]

As an example, querying for the device info::

    CoAP GET /nlltpdu
    0001 0002 "di" 0002 0000

And the response::

    CoAP 2.04 Changed
    0001 0002 "di" 0003 0026 00 hwver[10] fwver[8] serial[11] eui64[8]

Commands are similar to queries, with POST as the method and any arguments carried in the second TLV::

    CoAP POST /nlltpdu
    0001 EP-LEN ENDPOINT 0002 ARG-LEN ARGS

As an example, turn on a bulb (if it isn't already) and set the color to a pleasing Halloween orange #F25C00::

    CoAP POST /nlltpdu
    0001 0007 "lb/0/oo" 0002 0001 01
    0001 0007 "lb/0/hu" 0002 0002 0017
    0001 0007 "lb/0/sa" 0002 0002 0064
    0001 0007 "lb/0/pb" 0002 0002 005f

/, /0, /1, /2 endpoints
-----------------------
The iOS application talks HAP over CoAP to these endpoints.

- / is for encrypted HAP PDUs

- /0 is equivalent to identify

- /1 is equivalent to pair-setup

- /2 is equivalent to pair-verify

New HAP PDUs
^^^^^^^^^^^^
So far multiple new PDU opcodes have been seen versus what is publicly available. After pair-setup and pair-verify, the Home app sends opcode ``0x09`` to the accessory. The reply appears to be a GATT attribute table of sorts. Replying with this data to the Home app causes pairing to complete and it prompts for a name and room for the accessory. The app then begins to query the accessory in the background with HAP-Characteristic-Read (``0x0x3``) and another unknown opcode, ``0x0b`` (starts a subscription to a characteristic).

Communicating with a control point
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Performing a function like list pairings or remove pairings is no longer a simple REST call away. You must first write your request to the control point and then read the return code. You must then read the actual result from the control point.

- find "list pairings" characteristic IID

- construct State=M1 and Method=ListPairings TLV

- encode that TLV inside a HAP Param Value TLV

- construct a HAP PDU with opcode Characteristic Write for the "list pairings" IID

- write the encrypted request and decrypt the response

- construct a HAP PDU with opcode Characteristic Read for the "list pairings" IID

- write the encrypted request and decrypt the response

- unwrap the expected "list pairings" M2 response TLV from a HAP Param Value TLV

The "remove pairing" operation takes place over the "list pairing" characteristic.

Nanoleaf control point
^^^^^^^^^^^^^^^^^^^^^^
The hidden HAP characteristic at UUID bdeeeece-7100-0fa1-374d-a1cf02198ea2/a28e1902-cfa1-4d37-a10f-0071ceeeeebd (not sure which order the bytes go) supports some sort of Thread control. The Nanoleaf app sends the Thread network info packed in the TLV frame format described above in the nlXXX endpoint sections.

New Nanoleaf TLV tags:

0x0201::

    ?

0x0202::

    Read EUI64

    TAG  LEN  DATA
    0202 0002 0000

    Response

    TAG  LEN  DATA (REDACTED)
    8202 0008 ......fffe......

0x0703::

    ?

0x0704::

    ?

0x0707::

    ?

0x0801::

    TAG  L0   RW TAG  L1   EP    TAG  L2   TLV8
    0801 004b 01 0001 0005 ascii 0002 003d ...

    L0: overall length
    RW: 0=read, 1=write
    L1: length of endpoint (0001) tag
    EP: ascii string indicating command target
    L2: length of argument (0002) tag

    Currently known endpoints:
      ac/en: ?
      th/tc: Thread network info

    Top-level TLV8 tags:
      1: unknown, seen as TLV 01 01 01
      2: Thread network info
      3: unknown, seen as TLV 03 01 00

    Thread network info TLV8 tags:
      1: NetworkName (16 byte ascii string)
      2: Channel (1 byte int)
      3: PanID (2 byte int)
      4: ExtendedPanID (8 byte int)
      5: MasterKey (16 byte data)

