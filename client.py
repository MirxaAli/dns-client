import socket, struct, sys, random, time, re

RESOLVER = ("8.8.8.8", 53)
TIMEOUT = 5
MAX_TX = 3
LABEL = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
TYPES = {1: "A", 5: "CNAME"}
CLASSES = {1: "IN"}


class ParseError(Exception):
    def __init__(self, msg, offset):
        super().__init__(msg)
        self.msg = msg
        self.offset = offset


def hexs(b):
    return " ".join(f"{x:02x}" for x in b)


def valid_hostname(h):
    if not (1 <= len(h) <= 253) or h.endswith("."):
        return False
    return all(LABEL.fullmatch(l) for l in h.split("."))


def encode_qname(h):
    out = b""
    for label in h.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def read_name(msg, off):
    labels, pos, end, total = [], off, None, 1
    while True:
        if pos >= len(msg):
            raise ParseError("read past end of datagram", pos)
        b = msg[pos]
        if b & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise ParseError("pointer past end of datagram", pos)
            target = ((b & 0x3F) << 8) | msg[pos + 1]
            if target >= pos:
                raise ParseError("pointer does not point earlier", pos)
            if end is None:
                end = pos + 2
            pos = target
        elif b & 0xC0 == 0:
            if b == 0:
                if end is None:
                    end = pos + 1
                break
            if pos + 1 + b > len(msg):
                raise ParseError("label past end of datagram", pos)
            total += b + 1
            if total > 255:
                raise ParseError("name longer than 255 bytes", pos)
            labels.append(msg[pos + 1:pos + 1 + b].decode("ascii", "replace"))
            pos += 1 + b
        else:
            raise ParseError("invalid label type (bits 01/10)", pos)
    return ".".join(labels), end


def parse_record(msg, off, section, n):
    name, off = read_name(msg, off)
    if off + 10 > len(msg):
        raise ParseError("record fields past end of datagram", off)
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
    rd = off + 10
    rd_end = rd + rdlen
    if rd_end > len(msg):
        raise ParseError("RDATA past end of datagram", rd)
    ip = None
    if rtype == 1:
        if rdlen != 4:
            raise ParseError("A record with RDLENGTH != 4", off + 8)
        rdata = ".".join(str(x) for x in msg[rd:rd_end])
        if rclass == 1:
            ip = rdata
    elif rtype == 5:
        rdata, _ = read_name(msg, rd)
    else:
        rdata = hexs(msg[rd:rd_end])
    tname = TYPES.get(rtype, str(rtype))
    cname = CLASSES.get(rclass, str(rclass))
    print(f"  [{section} {n}] NAME={name}")
    print(f"    TYPE=0x{rtype:04x} ({tname}) CLASS=0x{rclass:04x} ({cname}) TTL=0x{ttl:08x} ({ttl})")
    print(f"    RDLENGTH=0x{rdlen:04x} ({rdlen})")
    print(f"    RDATA={rdata}")
    return rd_end, ip


def handle_reply(msg):
    print(f"=== DNS response ({len(msg)} bytes) ===")
    print("Raw hex:\n  " + hexs(msg))
    rid, flags, qd, an, ns, ar = struct.unpack("!6H", msg[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    z = (flags >> 4) & 7
    rcode = flags & 0xF
    print("Header:")
    print(f"  ID      0x{rid:04x}")
    print(f"  Flags   0x{flags:04x}")
    print(f"    QR={qr} OPCODE={opcode} AA={aa} TC={tc} RD={rd} RA={ra} Z={z} "
          f"RCODE={rcode} ({RCODES.get(rcode, 'UNKNOWN')})")
    print(f"  QDCOUNT 0x{qd:04x} ({qd})")
    print(f"  ANCOUNT 0x{an:04x} ({an})")
    print(f"  NSCOUNT 0x{ns:04x} ({ns})")
    print(f"  ARCOUNT 0x{ar:04x} ({ar})")
    a_ips = []
    try:
        qn, off = read_name(msg, 12)
        if off + 4 > len(msg):
            raise ParseError("question fields past end of datagram", off)
        qt, qc = struct.unpack("!HH", msg[off:off + 4])
        off += 4
        print("Question:")
        print(f"  QNAME={qn} QTYPE=0x{qt:04x} (A) QCLASS=0x{qc:04x} (IN)")
        for section, count in (("Answer", an), ("Authority", ns), ("Additional", ar)):
            print(f"{section} section ({count} records):")
            for i in range(1, count + 1):
                off, ip = parse_record(msg, off, section, i)
                if section == "Answer" and ip:
                    a_ips.append(ip)
        if off != len(msg):
            raise ParseError(f"{len(msg) - off} leftover byte(s) after last record", off)
    except ParseError as e:
        print("=== Outcome ===")
        print(f"FAILURE: reply rejected: {e.msg} (byte offset {e.offset})")
        return 1
    print("=== Outcome ===")
    problems = []
    if rcode != 0:
        problems.append(f"RCODE {rcode} ({RCODES.get(rcode, 'UNKNOWN')})")
    if tc:
        problems.append("reply truncated (TC=1)")
    if not a_ips:
        problems.append("no A records")
    if problems:
        print("FAILURE: " + "; ".join(problems))
        return 1
    print(f"SUCCESS: {len(a_ips)} IPv4 address(es): {', '.join(a_ips)}")
    return 0


if len(sys.argv) != 2 or not valid_hostname(sys.argv[1]):
    print("usage: client <hostname>  (missing, extra, or invalid hostname)", file=sys.stderr)
    sys.exit(1)
host = sys.argv[1]

qid = random.randint(0, 0xFFFF)
header = struct.pack("!6H", qid, 0x0100, 1, 0, 0, 0)
qname = encode_qname(host)
question = qname + struct.pack("!HH", 1, 1)
query = header + question

print("=== DNS query ===")
print("Header:")
print(f"  ID      0x{qid:04x}")
print("  Flags   0x0100 (QR=0, OPCODE=0, RD=1)")
print("  QDCOUNT 0x0001")
print("  ANCOUNT 0x0000")
print("  NSCOUNT 0x0000")
print("  ARCOUNT 0x0000")
print("  Hex    ", hexs(header))
print("Question:")
print(f"  QNAME   {host}")
print(f"          {hexs(qname)}")
print("  QTYPE   0x0001 (A)")
print("  QCLASS  0x0001 (IN)")
print("  Hex    ", hexs(question))
print(f"Full query ({len(query)} bytes):")
print("  " + hexs(query))
print(f"Destination: {RESOLVER[0]}:{RESOLVER[1]} (UDP over IPv4)")


def acceptable(data, addr):
    if addr != RESOLVER:
        return False
    if len(data) < 12:
        return False
    rid, flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
    if rid != qid or not (flags & 0x8000) or qd != 1:
        return False
    try:
        name, off = read_name(data, 12)
    except ParseError:
        return False
    if off + 4 > len(data):
        return False
    qtype, qclass = struct.unpack("!HH", data[off:off + 4])
    return name.lower() == host.lower() and qtype == 1 and qclass == 1


status = 1
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("Socket created")
try:
    sock.connect(RESOLVER)
    port = sock.getsockname()[1]
    reply = None
    for attempt in range(1, MAX_TX + 1):
        tag = f"Attempt {attempt}/{MAX_TX}"
        try:
            sock.send(query)
        except OSError as e:
            print(f"{tag}: failed: {e}")
            continue
        print(f"{tag}: sent {len(query)} bytes from local port {port}")
        deadline = time.monotonic() + TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print(f"{tag}: timed out after {TIMEOUT} s")
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                print(f"{tag}: timed out after {TIMEOUT} s")
                break
            except OSError as e:
                print(f"{tag}: failed: {e}")
                break
            if not acceptable(data, addr):
                continue
            print(f"{tag}: received valid reply")
            reply = data
            break
        if reply:
            break
    if reply is None:
        print("=== Outcome ===")
        print(f"FAILURE: no valid reply after {MAX_TX} transmissions")
        status = 1
    else:
        status = handle_reply(reply)
finally:
    sock.close()
    print("Socket closed")
sys.exit(status)
