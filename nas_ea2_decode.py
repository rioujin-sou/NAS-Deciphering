#!/usr/bin/env python3
"""
nas_ea2_decode.py - decrypt 5GS NAS messages protected with 128-5G-EA2 / 128-5G-IA2.

NAS EA2 Decoder:

Decoder Logic:

1. If no SUPI, K_SEAF, or K_AMF is provided by the user, the script searches the trace for
   keys: K_SEAF (and the SUPI) in the N12 authentication messages between the AMF and the
   AUSF, and - for 4G <-> 5G interworking (N26) - an EPS security context (K_ASME) carried
   over GTPv2, from which it derives a mapped K_AMF (TS 33.501 Annex A.14). Every key found
   becomes one security context, so a trace with several UEs is decrypted in one pass.

2. If SUPI cannot be extracted from the N12 authentication messages, the script searches for
   it inside the N2 messages between the AMF and the gNB.

3. The script uses K_SEAF to derive K_AMF using the SUPI and the ABBA parameter (TS 33.501
   Annex A.7). K_AMF can also be given directly.

4. Derives K_NASenc and K_NASint from K_AMF (TS 33.501 Annex A.8, algorithm id 2).

5. For every security-protected NAS PDU it finds the NAS COUNT. Only the low 8 bits
   (the sequence number) are on the wire, so the 16-bit overflow counter is tracked per
   direction and CONFIRMED by recomputing the 128-5G-IA2 MAC (AES-CMAC).

6. Decrypts the payload with 128-5G-EA2 (AES-128-CTR, TS 33.501 Annex D.2.2).

7. Prints a table and, with --out-n2-pcap, writes a copy of your N2 capture in which the
   ciphered NAS payloads are replaced by their plaintext: same length, same packets, with
   the SCTP checksum fixed. Opens in Wireshark with no configuration at all.
   NAS is read from ngap.NAS_PDU, ngap.nAS_PDU and ngap.pDUSessionNAS_PDU.

Inputs (pick one)

  --pcap N2.pcap [--amf-ip 10.0.0.1] extract NAS PDUs with tshark (ngap.NAS_PDU);

                                     packets sent BY the AMF are downlink, the rest uplink.

                                     Without --amf-ip, the AMF is the destination address of

                                     the first non-ciphered Registration Request (0x41)

  --list pdus.txt                    text file, one PDU per line:  <frame> <UL|DL> <hex>



Key inputs

  --kseaf <64 hex> [--supi <IMSI digits or imsi-...>] [--abba <hex>, default 0000]

  --kamf <64 hex>                    alternative: give K_AMF directly

  Both options may be repeated (one value per security context); --supi and --abba are
  shared by all --kseaf values. Only IMSI-type SUPIs are supported. Without --supi, the
  SUPI is read from the first null-scheme SUCI in a Registration Request or Identity
  Response; a SUCI concealed with ECIES (Profile A/B) or a 5G-GUTI cannot be used.

A MAC that verifies proves that the key chain (K_SEAF, SUPI, ABBA), the algorithm choice,
COUNT, bearer, and direction are all correct. If it does not verify, the "plain" output for
that message is a guess.

Requires: python3, the 'cryptography' package, and tshark only for --pcap.
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import ipaddress
import struct
import subprocess
import sys
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

UL, DL = 0, 1
DIR_NAME = {UL: "UL", DL: "DL"}
BEARER_3GPP = 1            # 1 = 3GPP access, 2 = non-3GPP access
ALG_EA2 = ALG_IA2 = 2      # 128-5G-EA2 / 128-5G-IA2 algorithm identities

SHT_NAME = {
    0: "plain",
    1: "integrity",
    2: "integrity+ciphered",
    3: "integrity (new ctx)",
    4: "integrity+ciphered (new ctx)",
}

MM_TYPES = {
    0x41: "Registration Request", 0x42: "Registration Accept",
    0x43: "Registration Complete", 0x44: "Registration Reject",
    0x45: "Deregistration Request (UE orig)", 0x46: "Deregistration Accept (UE orig)",
    0x47: "Deregistration Request (UE term)", 0x48: "Deregistration Accept (UE term)",
    0x4C: "Service Request", 0x4D: "Service Reject", 0x4E: "Service Accept",
    0x54: "Configuration Update Command", 0x55: "Configuration Update Complete",
    0x56: "Authentication Request", 0x57: "Authentication Response",
    0x58: "Authentication Reject", 0x59: "Authentication Failure",
    0x5A: "Authentication Result", 0x5B: "Identity Request", 0x5C: "Identity Response",
    0x5D: "Security Mode Command", 0x5E: "Security Mode Complete",
    0x5F: "Security Mode Reject", 0x64: "5GMM Status", 0x65: "Notification",
    0x66: "Notification Response", 0x67: "UL NAS Transport", 0x68: "DL NAS Transport",
}
SM_TYPES = {0xC1: "PDU Session Establishment Request",
            0xC2: "PDU Session Establishment Accept",
            0xC3: "PDU Session Establishment Reject"}


# --------------------------------------------------------------------------- crypto
def kdf_nas_key(k_amf: bytes, alg_type: int, alg_id: int) -> bytes:
    """TS 33.501 Annex A.8. alg_type: 0x01 = NAS enc, 0x02 = NAS int.
    S = FC(0x69) || P0 || L0(0x0001) || P1 || L1(0x0001); key = low 128 bits of HMAC-SHA-256."""
    s = bytes([0x69, alg_type, 0x00, 0x01, alg_id, 0x00, 0x01])
    return hmac.new(k_amf, s, hashlib.sha256).digest()[16:]


FC_KAMF = 0x6D


def derive_kamf(k_seaf: bytes, supi: str, abba: bytes) -> bytes:
    """TS 33.501 Annex A.7.0: K_AMF = HMAC-SHA-256(K_SEAF, S) with
    S = FC(0x6D) || P0 || L0 || P1 || L1, P0 = SUPI, P1 = ABBA, L0/L1 = 2-byte lengths.
    For an IMSI the SUPI is the digit string as ASCII characters (no 'imsi-' prefix),
    which is how open implementations such as Open5GS and free5GC encode it."""
    p0 = supi.encode("ascii")
    s = (bytes([FC_KAMF]) + p0 + struct.pack(">H", len(p0))
         + abba + struct.pack(">H", len(abba)))
    return hmac.new(k_seaf, s, hashlib.sha256).digest()


FC_KAMF_MAPPED = 0x75


def derive_kamf_mapped(k_asme: bytes, ul_nas_count: int) -> bytes:
    """TS 33.501 Annex A.14: mapped K'_AMF = HMAC-SHA-256(K_ASME, S) with
    S = FC(0x75) || P0 || L0, P0 = uplink NAS COUNT (4 bytes), L0 = 0x0004.
    Used for EPS -> 5GS interworking (N26): the EPS security context (K_ASME and the NAS
    uplink COUNT) is carried to the AMF over GTPv2, and the AMF maps it to a 5G K_AMF."""
    s = bytes([FC_KAMF_MAPPED]) + struct.pack(">I", ul_nas_count) + struct.pack(">H", 4)
    return hmac.new(k_asme, s, hashlib.sha256).digest()


def _block_tail(bearer: int, direction: int) -> int:
    return (bearer << 3) | (direction << 2)


def ea2(key: bytes, count: int, bearer: int, direction: int, data: bytes) -> bytes:
    """128-5G-EA2 = AES-128-CTR. Counter block: COUNT(32) | BEARER(5) | DIR(1) | 0(26) | 0(64).
    Encryption and decryption are the same operation."""
    iv = struct.pack(">I", count) + bytes([_block_tail(bearer, direction)]) + bytes(11)
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


def ia2(key: bytes, count: int, bearer: int, direction: int, msg: bytes) -> bytes:
    """128-5G-IA2 = first 32 bits of AES-CMAC over COUNT|BEARER|DIR|0(26) || message."""
    m = CMAC(algorithms.AES(key))
    m.update(struct.pack(">I", count) + bytes([_block_tail(bearer, direction)]) + bytes(3) + msg)
    return m.finalize()[:4]


# --------------------------------------------------------------------------- decoding
@dataclass
class KeySet:
    label: str
    k_enc: bytes
    k_int: bytes
    k_amf: bytes = b""
    k_seaf: bytes = b""
    k_asme: bytes = b""
    source: str = ""


def parse_key(name: str, hex_str: str) -> bytes:
    h = hex_str.lower().replace("0x", "").replace(":", "").replace(" ", "")
    try:
        k = bytes.fromhex(h)
    except ValueError:
        raise SystemExit(f"{name} is not valid hex")
    if len(k) != 32:
        raise SystemExit(f"{name} must be 32 bytes (64 hex chars), got {len(k)} bytes")
    return k


def parse_key_b64(name: str, b64_str: str) -> bytes:
    """A 32-byte key written in base64 (44 characters ending in '='), as some tools log it."""
    try:
        k = base64.b64decode(b64_str.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise SystemExit(f"{name} is not valid base64")
    if len(k) != 32:
        raise SystemExit(f"{name} must decode to 32 bytes (44 base64 chars), got {len(k)} bytes")
    return k


def norm_supi(supi: str) -> str:
    s = supi.strip()
    if s.lower().startswith("imsi-"):
        s = s[5:]
    if not (s.isascii() and s.isdigit()):
        raise SystemExit("--supi: expected the IMSI digits, optionally prefixed with 'imsi-'")
    return s


def make_keyset(label: str, k_amf: bytes, k_seaf: bytes = b"", k_asme: bytes = b"",
                source: str = "") -> KeySet:
    return KeySet(label, kdf_nas_key(k_amf, 0x01, ALG_EA2), kdf_nas_key(k_amf, 0x02, ALG_IA2),
                  k_amf, k_seaf, k_asme, source)


@dataclass
class DirState:
    overflow: int = 0
    last_sqn: int = -1
    key_idx: int = 0


@dataclass
class Result:
    status: str            # plain | ok | mac-fail | unparsable | not-5gmm
    sht: int = 0
    count: int = -1
    key: str = ""
    plain: bytes = b""
    note: str = ""


def process(pdu: bytes, direction: int, keysets, st: DirState, max_overflow: int) -> Result:
    if len(pdu) < 3 or pdu[0] != 0x7E:
        return Result("not-5gmm", plain=pdu)
    sht = pdu[1] & 0x0F
    if sht == 0:
        return Result("plain", plain=pdu)
    if sht > 4 or len(pdu) < 8:
        return Result("unparsable", sht=sht)

    mac, sqn, body = pdu[2:6], pdu[6], pdu[7:]
    signed = pdu[6:]                     # SQN + (ciphered) NAS message; MAC covers ciphertext
    ciphered = sht in (2, 4)

    guess = 0 if st.last_sqn < 0 else st.overflow + (1 if sqn < st.last_sqn else 0)
    if sht in (3, 4):                    # new security context: COUNT restarts at 0
        cands = list(range(max_overflow + 1))
    else:
        cands = [guess] + [o for o in range(max_overflow + 1) if o != guess]

    order = [st.key_idx] + [i for i in range(len(keysets)) if i != st.key_idx]
    for ki in order:
        ks = keysets[ki]
        for ov in cands:
            count = (ov << 8) | sqn
            if ia2(ks.k_int, count, BEARER_3GPP, direction, signed) == mac:
                plain = ea2(ks.k_enc, count, BEARER_3GPP, direction, body) if ciphered else body
                st.overflow, st.last_sqn, st.key_idx = ov, sqn, ki
                return Result("ok", sht, count, ks.label, plain)

    # A message labelled "integrity only" whose MAC fails may have been ciphered originally and
    # decrypted in place afterwards (payload replaced, header relabelled, MAC left as it was).
    # The MAC is computed over the CIPHERTEXT, so re-encrypt the payload and check again.
    if not ciphered:
        for ki in order:
            ks = keysets[ki]
            for ov in cands:
                count = (ov << 8) | sqn
                ct = ea2(ks.k_enc, count, BEARER_3GPP, direction, body)
                if ia2(ks.k_int, count, BEARER_3GPP, direction, bytes([sqn]) + ct) == mac:
                    st.overflow, st.last_sqn, st.key_idx = ov, sqn, ki
                    return Result("ok", sht, count, ks.label, body,
                                  "already decrypted in the capture; MAC verified over the re-encrypted payload")

    # No MAC verified: decrypt with the tracked COUNT so the user can still look, flagged.
    count = (guess << 8) | sqn
    ks = keysets[st.key_idx]
    plain = ea2(ks.k_enc, count, BEARER_3GPP, direction, body) if ciphered else body
    return Result("mac-fail", sht, count, ks.label, plain)


def describe(plain: bytes) -> str:
    if len(plain) < 3:
        return "(too short)"
    if plain[0] == 0x7E:
        return "5GMM " + MM_TYPES.get(plain[2], f"type 0x{plain[2]:02x}")
    if plain[0] == 0x2E and len(plain) >= 4:
        return "5GSM " + SM_TYPES.get(plain[3], f"type 0x{plain[3]:02x}")
    return f"EPD 0x{plain[0]:02x}"


# --------------------------------------------------------------------------- input / output
def parse_hex(s: str) -> bytes:
    return bytes.fromhex(s.strip().lower().replace(":", "").replace(" ", "").replace("0x", ""))


def read_list(path):
    out = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) != 3 or parts[1].upper() not in ("UL", "DL"):
                raise SystemExit(f"{path}:{n}: expected '<frame> <UL|DL> <hex>'")
            out.append((int(parts[0]), UL if parts[1].upper() == "UL" else DL, parse_hex(parts[2])))
    return out


def _is_amf(addr_field, amf):
    """True if any comma-separated address in addr_field equals the AMF address.
    Compares parsed addresses, so IPv6 spelling (case, zero compression) does not matter."""
    for s in addr_field.split(","):
        s = s.strip()
        if not s:
            continue
        try:
            if ipaddress.ip_address(s) == amf:
                return True
        except ValueError:
            pass
    return False


def is_registration_request(pdu: bytes) -> bool:
    """True for a 5GMM Registration Request that is readable on the wire:
    plain (SHT 0) or integrity protected but not ciphered (SHT 1 or 3)."""
    if len(pdu) < 3 or pdu[0] != 0x7E:
        return False
    sht = pdu[1] & 0x0F
    if sht == 0:
        return pdu[2] == 0x41
    if sht in (1, 3) and len(pdu) >= 10:           # 7-byte security header, then the plain message
        return pdu[7] == 0x7E and pdu[9] == 0x41
    return False


def _bcd(data: bytes) -> str:
    """Swapped-nibble BCD digits (low nibble first); 0xF is filler."""
    return "".join(f"{n:x}" for b in data for n in (b & 0x0F, b >> 4) if n != 0xF)


def supi_from_suci(mi: bytes):
    """5GS mobile identity contents (TS 24.501 9.11.3.4) -> (SUPI digits, None) for an IMSI-type
    SUCI with the null protection scheme, otherwise (None, reason it cannot be used)."""
    if not mi:
        return None, "empty mobile identity"
    id_type, supi_fmt = mi[0] & 0x07, (mi[0] >> 4) & 0x07
    if id_type != 1:
        names = {2: "5G-GUTI", 3: "IMEI", 4: "5G-S-TMSI", 5: "IMEISV"}
        return None, f"identity is {names.get(id_type, f'type {id_type}')}, not a SUCI"
    if supi_fmt != 0:
        return None, "SUCI is not IMSI-based"
    if len(mi) < 9:
        return None, "SUCI too short"
    scheme = mi[6] & 0x0F
    if scheme != 0:
        return None, f"SUCI is concealed (protection scheme {scheme}, ECIES)"
    mcc = f"{mi[1] & 0x0F:x}{mi[1] >> 4:x}{mi[2] & 0x0F:x}"
    mnc = f"{mi[3] & 0x0F:x}{mi[3] >> 4:x}" + ("" if mi[2] >> 4 == 0xF else f"{mi[2] >> 4:x}")
    supi = mcc + mnc + _bcd(mi[8:])
    if not supi.isdigit():
        return None, "SUCI contains non-decimal digits"
    return supi, None


def detect_supi(pdus):
    """SUPI from the first readable Registration Request (0x41) or Identity Response (0x5C)
    carrying a null-scheme SUCI. Returns (supi, frame, []) or (None, None, [reasons it failed])."""
    reasons = []
    for frame, _direction, pdu in pdus:
        if len(pdu) < 3 or pdu[0] != 0x7E:
            continue
        sht = pdu[1] & 0x0F
        msg = pdu if sht == 0 else pdu[7:] if sht in (1, 3) else b""
        if len(msg) < 3 or msg[0] != 0x7E or msg[2] not in (0x41, 0x5C):
            continue
        off = 4 if msg[2] == 0x41 else 3        # Registration Request has the type/ngKSI octet
        if len(msg) < off + 2:
            continue
        ln = int.from_bytes(msg[off:off + 2], "big")
        supi, why = supi_from_suci(msg[off + 2:off + 2 + ln])
        if supi:
            return supi, frame, []
        reasons.append(f"frame {frame}: {why}")
    return None, None, reasons or ["no readable Registration Request or Identity Response found"]


def detect_amf(rows):
    """AMF address = destination of the first readable Registration Request (sent UE -> AMF).
    Returns (address, frame)."""
    for frame, _src, dst, pdus in rows:
        if any(is_registration_request(p) for p in pdus):
            for s in dst.split(","):
                try:
                    amf = ipaddress.ip_address(s.strip())
                except ValueError:
                    continue
                return amf, frame
    raise SystemExit("--amf-ip not given and no readable Registration Request (0x41) found "
                     "to detect it from; pass --amf-ip")


def run_tshark(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        raise SystemExit("tshark not found; install it, pass --tshark PATH, or use --list")
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"tshark failed: {e.stderr.strip()}")


@dataclass
class N12Key:
    frame: int
    supi: str              # IMSI digits, "" if the authentication could not be tied to a SUPI
    supi_frame: int        # frame the SUPI was read from (0 if none)
    k_seaf: bytes


def supi_from_n12(value: str) -> str:
    """IMSI digits from a SBI supi / supiOrSuci string, or "" if it does not reveal one.
    imsi-<digits> is the SUPI itself; suci-0-<mcc>-<mnc>-<routing>-0-<key id>-<msin> is an
    IMSI-based SUCI with the null scheme (TS 29.503 SuciInfo), whose MSIN is in clear."""
    v = value.strip().lower()
    if v.startswith("imsi-") and v[5:].isdigit():
        return v[5:]
    parts = v.split("-")
    if len(parts) == 8 and parts[0] == "suci" and parts[1] == "0" and parts[5] == "0":
        digits = parts[2] + parts[3] + parts[7]
        if digits.isdigit():
            return digits
    return ""


def _auth_ctx_id(url: str) -> str:
    """'.../ue-authentications/<authCtxId>[/...]' -> authCtxId."""
    parts = url.split("?")[0].split("/")
    if "ue-authentications" in parts:
        i = parts.index("ue-authentications")
        if i + 1 < len(parts):
            return parts[i + 1]
    return ""


def read_n12(path, tshark, ports=(), keylog=None):
    """K_SEAF and SUPI from the Nausf_UEAuthentication exchanges in an N12 capture.

    POST /ue-authentications             request: supiOrSuci;  201: Location .../{authCtxId}
    PUT  .../{authCtxId}/5g-aka-confirmation  (5G AKA)  200: authResult, kseaf, [supi]
    POST .../{authCtxId}/eap-session          (EAP-AKA') 200: authResult, kSeaf, [supi]

    Request and response travel on one HTTP/2 stream, so they are grouped per stream; the
    authCtxId then ties the key to the SUPI of the request that started the authentication.
    Returns ([N12Key, ...], {supi: first frame it was seen in})."""
    sep = "\x1f"                                   # aggregator that cannot appear in the values
    cmd = [tshark, "-r", path]
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    for port in ports:
        cmd += ["-d", f"tcp.port=={port},{'tls' if keylog else 'http2'}"]
    cmd += ["-Y", 'http2.headers.path contains "ue-authentications" || '
                  'http2.headers.location contains "ue-authentications" || '
                  'json.key == "supiOrSuci" || json.key == "kseaf" || json.key == "kSeaf"',
            "-T", "fields", "-e", "frame.number", "-e", "tcp.stream", "-e", "http2.streamid",
            "-e", "http2.headers.path", "-e", "http2.headers.location", "-e", "json.path_with_value",
            "-E", "occurrence=a", "-E", f"aggregator={sep}"]

    streams = {}                                   # (tcp stream, h2 stream) -> exchange
    for line in run_tshark(cmd).splitlines():
        cols = (line.split("\t") + [""] * 6)[:6]
        frame, tcp, sids, path, loc, members = cols
        sid = next((x for x in sids.split(sep) if x not in ("", "0")), "0")
        ex = streams.setdefault((tcp, sid), {"path": "", "location": "", "json": {}})
        ex["path"] = ex["path"] or path.split(sep)[0]
        ex["location"] = ex["location"] or loc.split(sep)[0]
        for m in members.split(sep) if members else ():
            key, _, val = m[1:].partition(":")     # "/key:value"; deeper paths are not needed
            if m.startswith("/") and "/" not in key:
                ex["json"].setdefault(key, (val, int(frame)))

    ctx_supi, supis = {}, {}                       # authCtxId -> (supi, frame); supi -> frame
    for ex in streams.values():
        val, frame = ex["json"].get("supiOrSuci", ("", 0))
        supi = supi_from_n12(val)
        if supi:
            supis.setdefault(supi, frame)
            ctx = _auth_ctx_id(ex["location"])
            if ctx:
                ctx_supi[ctx] = (supi, frame)

    keys, seen = [], set()
    for ex in sorted(streams.values(), key=lambda e: min((f for _, f in e["json"].values()), default=0)):
        j = ex["json"]
        k, frame = j.get("kseaf") or j.get("kSeaf") or ("", 0)
        if not k or j.get("authResult", ("AUTHENTICATION_SUCCESS",))[0] != "AUTHENTICATION_SUCCESS":
            continue
        try:
            k_seaf = bytes.fromhex(k)
        except ValueError:
            k_seaf = b""
        if len(k_seaf) != 32:
            print(f"WARNING: N12 frame {frame}: K_SEAF '{k}' is not 32 bytes of hex, ignored",
                  file=sys.stderr)
            continue
        supi, supi_frame = "", 0
        if "supi" in j and supi_from_n12(j["supi"][0]):
            supi, supi_frame = supi_from_n12(j["supi"][0]), j["supi"][1]
        elif _auth_ctx_id(ex["path"]) in ctx_supi:
            supi, supi_frame = ctx_supi[_auth_ctx_id(ex["path"])]
        if supi:
            supis.setdefault(supi, supi_frame)
        if (supi, k_seaf) not in seen:             # same response captured twice
            seen.add((supi, k_seaf))
            keys.append(N12Key(frame, supi, supi_frame, k_seaf))
    return keys, supis


@dataclass
class MappedKey:
    frame: int
    supi: str              # IMSI digits from the GTPv2 message, "" if absent
    k_asme: bytes
    k_amf: bytes           # mapped K'_AMF derived from K_ASME (TS 33.501 Annex A.14)


def read_gtpv2(path, tshark):
    """Mapped 5G keys from an EPS security context carried over GTPv2 (EPS <-> 5GS, N26/S10).
    The MM Context IE of a Context Response or Forward Relocation Request holds K_ASME and the
    NAS uplink COUNT; each becomes one mapped K'_AMF. Returns [MappedKey, ...]."""
    sep = "\x1f"
    cmd = [tshark, "-r", path,
           "-Y", "gtpv2.mm_context_kasme", "-T", "fields",
           "-e", "frame.number", "-e", "e212.imsi", "-e", "gtpv2.mm_context_kasme",
           "-e", "gtpv2.mm_context_nas_ul_cnt",
           "-E", "occurrence=a", "-E", f"aggregator={sep}"]
    out, seen = [], set()
    for line in run_tshark(cmd).splitlines():
        frame, imsis, kasmes, ulcnts = (line.split("\t") + [""] * 4)[:4]
        imsi = next((x for x in imsis.split(sep) if x), "")
        for kasme_hex, ul in zip(kasmes.split(sep), ulcnts.split(sep)):
            try:
                k_asme = bytes.fromhex(kasme_hex)
                ul_count = int(ul)
            except ValueError:
                continue
            if len(k_asme) != 32 or (imsi, kasme_hex, ul_count) in seen:
                continue
            seen.add((imsi, kasme_hex, ul_count))
            out.append(MappedKey(int(frame), imsi if imsi.isdigit() else "",
                                 k_asme, derive_kamf_mapped(k_asme, ul_count)))
    return out


def read_pcap(path, amf_ip, tshark):
    """-> ([(frame, direction, NAS PDU), ...], AMF address, where the address came from)."""
    amf, amf_src = None, "--amf-ip"
    if amf_ip:
        try:
            amf = ipaddress.ip_address(amf_ip.strip().strip("[]"))
        except ValueError:
            raise SystemExit(f"--amf-ip: '{amf_ip}' is not a valid IPv4 or IPv6 address")
    # NAS can sit in ngap.NAS_PDU, ngap.nAS_PDU (e.g. InitialContextSetup PDU session items)
    # or ngap.pDUSessionNAS_PDU (PDUSessionResourceSetupRequest): ask for all three.
    cmd = [tshark, "-r", path, "-T", "fields",
           "-Y", "ngap.NAS_PDU || ngap.nAS_PDU || ngap.pDUSessionNAS_PDU",
           "-e", "frame.number", "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
           "-e", "ngap.NAS_PDU", "-e", "ngap.nAS_PDU", "-e", "ngap.pDUSessionNAS_PDU",
           "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    rows = []                                      # (frame, src addrs, dst addrs, [NAS PDUs])
    for line in run_tshark(cmd).splitlines():
        cols = line.split("\t")
        if len(cols) < 6:
            continue
        pdus = [parse_hex(h) for col in cols[5:] for h in col.split(",") if h.strip()]
        rows.append((int(cols[0]), cols[1] + "," + cols[2], cols[3] + "," + cols[4], pdus))
    if amf is None and rows:
        amf, frame = detect_amf(rows)
        amf_src = f"Registration Request in frame {frame}"
    out = []
    for frame, src, _dst, pdus in rows:
        direction = DL if _is_amf(src, amf) else UL
        out.extend((frame, direction, p) for p in pdus)
    if not out:
        print("tshark returned no NAS PDUs. Check the field name with:\n"
              "  tshark -G fields | grep -i nas_pdu", file=sys.stderr)
    return out, amf, amf_src


# --------------------------------------------------------------------------- in-place N2 rewrite
def _crc32c_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


_CRC_T = _crc32c_table()


def crc32c(data) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC_T[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def find_sctp(frame, linktype):
    """(start, end) of the SCTP packet inside a captured frame, or None.
    Handles Ethernet (with VLAN tags), Linux cooked and raw IP, over IPv4 or IPv6."""
    try:
        if linktype == 1:
            off, et = 14, int.from_bytes(frame[12:14], "big")
            while et in (0x8100, 0x88A8, 0x9100):          # skip VLAN tags
                et = int.from_bytes(frame[off + 2:off + 4], "big")
                off += 4
        elif linktype == 113:
            off, et = 16, int.from_bytes(frame[14:16], "big")
        elif linktype in (12, 101):
            off, et = 0, (0x86DD if frame[0] >> 4 == 6 else 0x0800)
        else:
            return None
        if et == 0x86DD:
            nh = frame[off + 6]
            pos = off + 40
            end = min(len(frame), pos + int.from_bytes(frame[off + 4:off + 6], "big"))
            while nh in (0, 43, 60):                       # skip IPv6 extension headers
                nh, ln = frame[pos], frame[pos + 1]
                pos += (ln + 1) * 8
            return (pos, end) if nh == 132 else None
        if et == 0x0800 and frame[off + 9] == 132:
            ihl = (frame[off] & 0x0F) * 4
            total = int.from_bytes(frame[off + 2:off + 4], "big")
            return off + ihl, min(len(frame), off + total)
    except IndexError:
        pass
    return None


def read_classic_pcap(path):
    """-> (24-byte global header, linktype, [[16-byte record header, bytearray frame], ...]) or None."""
    raw = open(path, "rb").read()
    little = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    big = (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
    if raw[:4] not in little + big:
        return None
    e = "<" if raw[:4] in little else ">"
    linktype = struct.unpack(e + "I", raw[20:24])[0] & 0x0FFFFFFF
    recs, off = [], 24
    while off + 16 <= len(raw):
        incl = struct.unpack(e + "I", raw[off + 8:off + 12])[0]
        recs.append([raw[off:off + 16], bytearray(raw[off + 16:off + 16 + incl])])
        off += 16 + incl
    return raw[:24], linktype, recs


def rewrite_n2(src, dst, repl, tshark):
    """Copy the N2 capture to dst, replacing NAS PDUs in place.
    repl = {frame number: [(old pdu, new pdu of identical length), ...]}.
    Everything else stays byte-identical, except the SCTP checksum of each changed frame,
    which is recomputed (CRC32c). Returns (frames changed, list of problems)."""
    loaded = read_classic_pcap(src)
    tmp = None
    if loaded is None:                                     # pcapng etc.: let tshark convert
        tmp = dst + ".tmp.pcap"
        try:
            subprocess.run([tshark, "-r", src, "-F", "pcap", "-w", tmp],
                           capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            raise SystemExit(f"could not convert {src} to classic pcap with tshark: {e}")
        loaded = read_classic_pcap(tmp)
    gh, linktype, recs = loaded
    changed, problems = 0, []
    for frame_no, items in sorted(repl.items()):
        if not 1 <= frame_no <= len(recs):
            problems.append(f"frame {frame_no}: not in the capture")
            continue
        data = recs[frame_no - 1][1]
        used, did = [], False
        for old, new in items:
            assert len(old) == len(new)
            start, pos = 0, -1
            while True:
                p = data.find(old, start)
                if p < 0 or not any(p < ue and us < p + len(old) for us, ue in used):
                    pos = p
                    break
                start = p + 1
            if pos < 0:
                problems.append(f"frame {frame_no}: NAS PDU bytes not found in the packet "
                                "(split over several packets?)")
                continue
            data[pos:pos + len(old)] = new
            used.append((pos, pos + len(old)))
            did = True
        if not did:
            continue
        loc = find_sctp(bytes(data), linktype)
        if loc is None:
            problems.append(f"frame {frame_no}: SCTP header not located, checksum NOT updated")
        else:
            s, e = loc
            data[s + 8:s + 12] = b"\x00\x00\x00\x00"
            data[s + 8:s + 12] = struct.pack("<I", crc32c(bytes(data[s:e])))
        changed += 1
    with open(dst, "wb") as f:
        f.write(gh)
        for rh, data in recs:
            f.write(rh)
            f.write(data)
    if tmp:
        import os
        os.remove(tmp)
    return changed, problems


def ask(question: str, option: str, why) -> str:
    """Ask at the terminal; when not interactive, stop and say which option to pass."""
    detail = "".join(f"\n  {r}" for r in why)
    if not sys.stdin.isatty():
        raise SystemExit(f"{question} could not be found:{detail}\nPass {option}.")
    if why:
        print(f"{question} could not be found:{detail}")
    try:
        return input(f"{question}: ").strip()
    except (EOFError, KeyboardInterrupt):
        raise SystemExit("\naborted")


def ask_supi(why) -> str:
    while True:
        try:
            return norm_supi(ask("SUPI (IMSI digits, optionally 'imsi-...')", "--supi", why))
        except SystemExit as e:
            if not sys.stdin.isatty():
                raise
            print(e)
            why = []


def ask_key(why):
    """-> ('kseaf' | 'kamf', 32-byte key)."""
    while True:
        answer = ask("K_SEAF or K_AMF (64 hex chars; prefix with 'kamf:' for a K_AMF)",
                     "--kseaf (with the SUPI) or --kamf", why)
        kind = "kamf" if answer.lower().startswith("kamf:") else "kseaf"
        for prefix in ("kamf:", "kseaf:"):
            if answer.lower().startswith(prefix):
                answer = answer[len(prefix):]
        try:
            return kind, parse_key("K_AMF" if kind == "kamf" else "K_SEAF", answer)
        except SystemExit as e:
            print(e)
            why = []


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="N2 capture to read with tshark")
    src.add_argument("--list", help="text file: '<frame> <UL|DL> <hex>' per line")
    ap.add_argument("--amf-ip",
                    help="AMF IPv4 or IPv6 address on N2, used with --pcap to tell DL from UL "
                         "(default: destination of the first readable Registration Request)")
    ap.add_argument("--kseaf", action="append", default=[],
                    help="K_SEAF as 64 hex chars; repeat for several security contexts "
                         "(default: read from the N12 signalling, else asked for)")
    ap.add_argument("--kseaf-ascii", action="append", default=[],
                    help="K_SEAF in base64 text, e.g. 'L7j/BJhZPB3mJKHeQEza2ds+gH0cPZ1ZBw2ZGX7/7io=' "
                         "(quote it); same use as --kseaf, repeatable")
    ap.add_argument("--supi", help="IMSI digits, optionally prefixed 'imsi-' (used with --kseaf); "
                                   "default: read from N12, else from a null-scheme SUCI on N2, "
                                   "else asked for")
    ap.add_argument("--n12-pcap",
                    help="capture with the N12 (AMF <-> AUSF) signalling to read K_SEAF and "
                         "the SUPI from (default: --pcap)")
    ap.add_argument("--n12-port", type=int, action="append", default=[],
                    help="TCP port of N12 to decode as HTTP/2 (or TLS with --tls-keylog); repeatable")
    ap.add_argument("--tls-keylog", help="TLS key log file (SSLKEYLOGFILE format) to decrypt N12")
    ap.add_argument("--abba", default="0000",
                    help="ABBA parameter in hex, from the Authentication Request (default 0000)")
    ap.add_argument("--kamf", action="append", default=[],
                    help="K_AMF as 64 hex chars, instead of --kseaf; repeatable")
    ap.add_argument("--show-keys", action=argparse.BooleanOptionalAction, default=True,
                    help="print the derived K_AMF, K_NASenc and K_NASint (default: on)")
    ap.add_argument("--view-msg", action="store_true",
                    help="print the list of NAS messages with their decoding (default: only a summary)")
    ap.add_argument("--max-overflow", type=int, default=255,
                    help="highest NAS COUNT overflow value to try when matching the MAC (default 255)")
    ap.add_argument("--out-n2-pcap",
                    help="copy of the N2 capture with the ciphered NAS decrypted in place "
                         "(needs --pcap); opens in Wireshark with no setup")
    ap.add_argument("--keep-unverified", action="store_true",
                    help="also decrypt messages whose MAC did not verify into --out-n2-pcap")
    ap.add_argument("--tshark", default="tshark")
    a = ap.parse_args()

    if a.out_n2_pcap and not a.pcap:
        ap.error("--out-n2-pcap needs --pcap (it rewrites the original capture)")

    try:
        abba = bytes.fromhex(a.abba.lower().replace("0x", "").replace(" ", ""))
    except ValueError:
        ap.error("--abba is not valid hex")

    amf = None
    if a.pcap:
        pdus, amf, amf_src = read_pcap(a.pcap, a.amf_ip, a.tshark)
    else:
        pdus = read_list(a.list)

    # Without ciphered NAS there is nothing to decrypt: skip the key and SUPI search.
    ciphered_frames = sorted({f for f, _, p in pdus
                              if len(p) >= 2 and p[0] == 0x7E and p[1] & 0x0F in (2, 4)})
    if not ciphered_frames:
        if amf is not None:
            print(f"AMF IP = {amf}   (from {amf_src})\n")
        if a.view_msg:
            print(f"{'frame':>6} {'dir':<3} {'security header':<28} message")
            for frame, direction, pdu in pdus:
                sht = pdu[1] & 0x0F if len(pdu) >= 2 and pdu[0] == 0x7E else 0
                body = pdu[7:] if sht in (1, 3) else pdu
                print(f"{frame:>6} {DIR_NAME[direction]:<3} {SHT_NAME.get(sht, '?'):<28} {describe(body)}")
            print()
        print(f"{len(pdus)} NAS messages, none ciphered: nothing to decrypt, "
              "so no K_SEAF or SUPI is needed.")
        if a.out_n2_pcap:
            print(f"{a.out_n2_pcap} not written: it would be identical to the input.")
        return
    print(f"{len(ciphered_frames)} frames with ciphered NAS "
          f"(first: frame {ciphered_frames[0]}); looking for the keys.\n")

    # Keys are gathered automatically from the trace - N12 K_SEAF (native 5G authentication)
    # and a mapped K_AMF from an EPS security context carried over GTPv2 (4G <-> 5G N26
    # interworking) - and from the command line. Every key found becomes a security context;
    # a multi-UE trace yields several, and each NAS message is tried against all of them.
    n12_path = a.n12_pcap or a.pcap
    kseaf_given = a.kseaf or a.kseaf_ascii
    want_auto = not kseaf_given and not a.kamf        # pull keys from the trace
    want_n12 = want_auto or (kseaf_given and not a.supi)   # also read N12 just for the SUPI
    n12_keys, n12_supis = (read_n12(n12_path, a.tshark, a.n12_port, a.tls_keylog)
                           if n12_path and want_n12 else ([], {}))
    mapped = read_gtpv2(a.pcap, a.tshark) if (a.pcap and want_auto) else []
    if not n12_path:
        n12_why = "no N12 capture (pass --n12-pcap, or --pcap with N12 in it)"
    else:
        n12_why = (f"no K_SEAF (N12 Nausf_UEAuthentication) or K_ASME (GTPv2 EPS context) in "
                   f"{n12_path} (N12 missing, on a port not decoded as HTTP/2: --n12-port, "
                   "or TLS: --tls-keylog)")

    # Each collected key is either a K_SEAF (needs a SUPI to make K_AMF) or a K_AMF already.
    # seaf entry: (K_SEAF, SUPI for this key or None to use the shared one, source)
    seaf = [(parse_key("--kseaf", ks), None, "--kseaf") for ks in a.kseaf]
    seaf += [(parse_key_b64("--kseaf-ascii", ks), None, "--kseaf-ascii") for ks in a.kseaf_ascii]
    # kamf entry: (K_AMF, K_ASME it was mapped from or b"", source)
    kamf = [(parse_key("--kamf", ks), b"", "--kamf") for ks in a.kamf]
    for m in mapped:
        kamf.append((m.k_amf, m.k_asme,
                     f"GTPv2 frame {m.frame}" + (f", imsi-{m.supi}" if m.supi else "")))
    if want_auto:
        for k in n12_keys:
            seaf.append((k.k_seaf, k.supi or None,
                         f"N12 frame {k.frame}" + (f", imsi-{k.supi}" if k.supi else "")))

    if not seaf and not kamf:
        kind, key = ask_key([n12_why])
        (seaf if kind == "kseaf" else kamf).append(
            (key, None, "the terminal") if kind == "kseaf" else (key, b"", "the terminal"))

    # A shared SUPI is needed only for K_SEAF values that do not carry their own (e.g. --kseaf).
    supi = supi_src = None
    if any(s is None for _, s, _ in seaf):
        why = []
        if a.supi:
            supi, supi_src = norm_supi(a.supi), "--supi"
        elif len(n12_supis) == 1:
            supi, frame = next(iter(n12_supis.items()))
            supi_src = f"N12 frame {frame}"
        else:
            why.append("N12: " + ("several UEs: " + ", ".join(f"imsi-{x}" for x in n12_supis)
                                  if n12_supis else
                                  "no SUPI (the response has no 'supi' and the request's "
                                  "'supiOrSuci' is a concealed SUCI or missing)" if n12_keys
                                  else n12_why))
            supi, frame, reasons = detect_supi(pdus)
            if supi:
                supi_src = f"null-scheme SUCI in N2 frame {frame}"
            else:
                why += [f"N2: {r}" for r in reasons]
                supi, supi_src = ask_supi(why), "the terminal"

    # Summary of the SUPIs across all contexts (one UE, or several in a multi-UE trace).
    supi_srcs = {}
    for _, s, src in seaf:
        v = s or supi
        if v and v not in supi_srcs:
            supi_srcs[v] = supi_src if s is None else src.split(",")[0]
    for m in mapped:
        if m.supi and m.supi not in supi_srcs:
            supi_srcs[m.supi] = f"GTPv2 frame {m.frame}"
    if len(supi_srcs) == 1:
        (v, src), = supi_srcs.items()
        print(f"SUPI   = imsi-{v}   (from {src})")
    elif supi_srcs:
        print("SUPIs  = " + ", ".join(f"imsi-{v} (from {src})" for v, src in supi_srcs.items()))
    if amf is not None:
        print(f"AMF IP = {amf}   (from {amf_src})")
    if supi_srcs or amf is not None:
        print()

    keysets = []
    for k_seaf, s, src in seaf:
        keysets.append(make_keyset(f"ctx#{len(keysets)}", derive_kamf(k_seaf, s or supi, abba),
                                   k_seaf=k_seaf, source=f"K_SEAF from {src}"))
    for k_amf, k_asme, src in kamf:
        label = ("mapped K_AMF from " + src) if k_asme else ("K_AMF from " + src)
        keysets.append(make_keyset(f"ctx#{len(keysets)}", k_amf, k_asme=k_asme, source=label))
    if a.show_keys:
        for k in keysets:
            print(f"{k.label}:   ({k.source})")
            if k.k_asme:
                print(f"  K_ASME   = {k.k_asme.hex()}")
            if k.k_seaf:
                print(f"  K_SEAF   = {k.k_seaf.hex()}")
            print(f"  K_AMF    = {k.k_amf.hex()}")
            print(f"  K_NASenc = {k.k_enc.hex()}")
            print(f"  K_NASint = {k.k_int.hex()}")
            print()

    state = {UL: DirState(), DL: DirState()}
    repl = {}
    tally = {}
    if a.view_msg:
        print(f"{'frame':>6} {'dir':<3} {'security header':<28} {'COUNT':>8} {'MAC':<8} {'key':<9} message")
    for frame, direction, pdu in pdus:
        r = process(pdu, direction, keysets, state[direction], a.max_overflow)
        tally[r.status] = tally.get(r.status, 0) + 1
        mac = {"ok": "ok", "mac-fail": "FAIL"}.get(r.status, "-")
        count = str(r.count) if r.count >= 0 else "-"
        sht = SHT_NAME.get(r.sht, "?")
        what = describe(r.plain) if r.plain else "-"
        ciphered = r.sht in (2, 4)
        if r.note:
            what += f"   ({r.note})"
        if r.status == "mac-fail":
            if ciphered:
                what += "   (UNVERIFIED - COUNT/key probably wrong)"
            else:
                what += "   (MAC not verified, but this message is not ciphered so it is readable)"
        usable = r.status in ("ok", "plain") or (r.status == "mac-fail" and (not ciphered or a.keep_unverified))
        if a.view_msg:
            print(f"{frame:>6} {DIR_NAME[direction]:<3} {sht:<28} {count:>8} {mac:<8} {r.key:<9} {what}")
            if r.plain and usable:
                print(f"{'':>6}     plain NAS: {r.plain.hex()}")
        if ciphered and r.plain and (r.status == "ok" or a.keep_unverified):
            # same length (EA2 is a stream cipher): keep the security header, put the plaintext
            # in the payload and relabel the header type "ciphered" -> "integrity only"
            new = bytes([0x7E, (pdu[1] & 0xF0) | (r.sht - 1)]) + pdu[2:7] + r.plain
            repl.setdefault(frame, []).append((pdu, new))

    names = {"ok": "MAC verified", "mac-fail": "MAC FAILED", "plain": "plain",
             "not-5gmm": "not 5GMM", "unparsable": "unparsable"}
    print(f"{'' if not a.view_msg else chr(10)}{len(pdus)} NAS messages: "
          + ", ".join(f"{n} {names[k]}" for k, n in tally.items())
          + ("" if a.view_msg else "   (--view-msg to list them)"))

    if a.out_n2_pcap:
        n_changed, problems = rewrite_n2(a.pcap, a.out_n2_pcap, repl, a.tshark)
        print(f"\nwrote {a.out_n2_pcap}: {n_changed} packets with NAS decrypted in place "
              f"(frames {', '.join(str(f) for f in sorted(repl))}); everything else is unchanged.")
        print("In those packets the security header type is relabelled from 'ciphered' to "
              "'integrity only' so Wireshark decodes the payload; the MAC field is the original one.")
        for p in problems:
            print("WARNING:", p, file=sys.stderr)


if __name__ == "__main__":
    main()
