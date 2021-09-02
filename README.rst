Documentation for the LTPDU API
===============================

The Essentials bulb by `nanoleaf <https://nanoleaf.me/>`_ recently gained local control via Thread. Using an Elements device as a Thread Border Router causes Essentials devices to be advertised via a mDNS service ``_ltpdu._udp``. Those services reference the standard CoAP port and accessing the `CoRE resource discovery endpoint <https://datatracker.ietf.org/doc/html/rfc6690#section-4>`_ reveals the following::

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

    CoAP POST /nlpublic
    0001 0007 6c622f302f6964 0002 0000
    Tag  Len  Endpoint       Tag  Len

Requests to this endpoint contain pairs of TLVs, the first designating the device's function (``lb/0/id`` in this case), and the second providing any arguments.

nlsecure endpoint
-----------------
This endpoint is used to authenticate to the device, either via 8-digit PIN or a previously obtained access token. A CoAP session must be authenticated by one of these two methods before proceeding to call further APIs.

To begin, a X25519 key exchange is performed::

    CoAP POST /nlsecure
    0101 0020 [public key bytes]

The response is as follows::

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

The PIN digits are passed as ASCII characters (0x30-0x39) not their binary representation (0x01-0x09). A successful response contains the access token::

    0104 0008 XXXXXXXX

The response is a 64-bit binary access token and should be securely stored for later use.

Access token authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^
To authenticate a CoAP session using an access token, send the following payload::

    CoAP POST /nlsecure
    0104 0008 XXXXXXXX

The 8-byte data field is identical to the data received in the PIN auth response.

nlltpdu endpoint
----------------
Queries to this endpoint follow the format of the nlpublic endpoint. Multiple queries can be concatenated in a single request payload; responses are returned concatenated in the same order as the request.

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

Requests for information use GET::

    CoAP GET /nlltpdu
    0001 LLLL ENDPOINT 0002 0000

Responses typically have their second TLV as type 0003 which contains a status code after the length but before the payload::

    0001 LLLL ENDPOINT 0003 LLLL SC XX[len-1]

As an example, querying for the device info::

    CoAP GET /nlltpdu
    0001 0002 "di" 0002 0000

And the response::

    CoAP 2.04 Changed
    0001 0002 "di" 0003 0026 00 hwver[10] fwver[8] serial[11] eui64[8]

Commands are similar to queries, with POST as the method and any arguments carried in the second TLV::

    CoAP POST /nlltpdu
    0001 LLLL ENDPOINT 0002 0001 01

