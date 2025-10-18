from binascii import unhexlify, hexlify
import struct, json, sys

# Accept tx hex on the command line for convenience, e.g.
#   python3 TxDecode.py <raw_tx_hex>
# If not provided, fall back to a short sample (likely too short for a full tx).
if len(sys.argv) > 1:
    tx_hex = sys.argv[1]
else:
    tx_hex = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5d032b040e04e159ea682f466f756e6472792055534120506f6f6c202364726f70676f6c642ffabe6d6de0504307417a699adc488bf7132a0aac87eeae54e2268a28ceca313a52c4a39901000000000000008792678bc6debb0000000000ffffffff048d5fc212000000002200207086320071974eef5e72eaa01dd9096e10c0383483855ea6b344259c244f73c20000000000000000266a24aa21a9ed673b73cad5cb0fa33cbac4cd82a5f0713f0f903f60205057882b49e4b3116fe400000000000000002f6a2d434f524501ebbaf365b0d5fa072e2b2429db23696291f2c038e6d18fda214e5b9f350ffc7b6cf3058b9026e76500000000000000002b6a2952534b424c4f434b3ac866a5852c6f708c961d6450dc3328e8171546a98f9fda3ff0286817007b6d880120000000000000000000000000000000000000000000000000000000000000000000000000"
data = unhexlify(tx_hex)
i = 0

def read_bytes(count):
    global i
    b = data[i:i+count]
    if len(b) < count:
        # gives helpful error when provided hex is too short / truncated
        raise EOFError(f"read_bytes: need {count} bytes at index {i}, but only {len(b)} available (data length {len(data)})")
    i += count
    return b

def read_uint32_le():
    global i
    b = read_bytes(4); return struct.unpack("<I", b)[0]

def read_uint64_le():
    global i
    b = read_bytes(8); return struct.unpack("<Q", b)[0]

def read_varint():
    global i
    # read one byte safely
    b = read_bytes(1)
    prefix = b[0]
    if prefix < 0xfd:
        return prefix
    if prefix == 0xfd:
        return struct.unpack("<H", read_bytes(2))[0]
    if prefix == 0xfe:
        return struct.unpack("<I", read_bytes(4))[0]
    return struct.unpack("<Q", read_bytes(8))[0]

parsed = {}
parsed['version'] = read_uint32_le()
is_segwit = False
if len(data) - i >= 2 and data[i] == 0x00 and data[i+1] == 0x01:
    is_segwit = True
    i += 2
parsed['is_segwit'] = is_segwit

vin_count = read_varint(); parsed['vin_count'] = vin_count; parsed['vin']=[]
for idx in range(vin_count):
    prev_txid = read_bytes(32); prev_txid_be = hexlify(prev_txid[::-1]).decode()
    prev_vout = struct.unpack("<I", read_bytes(4))[0]
    slen = read_varint(); script_sig = read_bytes(slen)
    sequence = struct.unpack("<I", read_bytes(4))[0]
    parsed['vin'].append({
        'index': idx,
        'prev_txid_le': hexlify(prev_txid).decode(),
        'prev_txid': prev_txid_be,
        'prev_vout': prev_vout,
        'script_sig': hexlify(script_sig).decode(),
        'sequence': sequence
    })

vout_count = read_varint(); parsed['vout_count'] = vout_count; parsed['vout']=[]
for idx in range(vout_count):
    value_sat = read_uint64_le(); value_btc = value_sat / 1e8
    pk_len = read_varint(); pk_script = read_bytes(pk_len)
    parsed['vout'].append({
        'index': idx,
        'value_sats': value_sat,
        'value_btc': value_btc,
        'script_pubkey': hexlify(pk_script).decode()
    })

if is_segwit:
    parsed['witness'] = []
    for _ in range(vin_count):
        count = read_varint(); items=[]
        for _ in range(count):
            item_len = read_varint(); items.append(hexlify(read_bytes(item_len)).decode())
        parsed['witness'].append(items)

parsed['locktime'] = read_uint32_le()
print(json.dumps(parsed, indent=2))
