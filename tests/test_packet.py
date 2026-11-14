"""Unit tests for the hand-rolled packet layer — all offline, no sockets."""

from scanner.packet import ipv4, tcp, udp, icmp
from scanner.packet.checksums import internet_checksum, transport_checksum


def test_internet_checksum_known_vector():
    # Two 16-bit words that sum without carry; complement is predictable.
    assert internet_checksum(b"\x00\x00") == 0xFFFF
    # A correct checksum, when included, makes the whole block sum to zero.
    data = b"\x45\x00\x00\x28\xab\xcd\x00\x00\x40\x06"
    cks = internet_checksum(data)
    assert internet_checksum(data + cks.to_bytes(2, "big")) == 0


def test_ipv4_build_parse_roundtrip():
    pkt = ipv4.build("192.168.1.10", "10.0.0.1", ipv4.PROTO_TCP, b"payload",
                     ttl=55, identification=0x1234)
    p = ipv4.parse(pkt)
    assert p is not None
    assert p.src == "192.168.1.10" and p.dst == "10.0.0.1"
    assert p.ttl == 55 and p.identification == 0x1234
    assert p.proto == ipv4.PROTO_TCP and p.payload == b"payload"
    # Header checksum must validate.
    assert internet_checksum(pkt[:20]) == 0


def test_ipv4_bad_checksum_flag_corrupts():
    good = ipv4.build("1.1.1.1", "2.2.2.2", ipv4.PROTO_TCP, b"x", identification=1)
    bad = ipv4.build("1.1.1.1", "2.2.2.2", ipv4.PROTO_TCP, b"x", identification=1, bad_checksum=True)
    assert good != bad
    assert internet_checksum(good[:20]) == 0
    assert internet_checksum(bad[:20]) != 0


def test_tcp_build_parse_and_flags():
    seg = tcp.build("1.1.1.1", "2.2.2.2", 40000, 443, seq=42,
                    flags=tcp.SYN | tcp.ACK, options=tcp.default_options())
    t = tcp.parse(seg)
    assert t.src_port == 40000 and t.dst_port == 443 and t.seq == 42
    assert t.has(tcp.SYN) and t.has(tcp.ACK) and not t.has(tcp.FIN)
    assert "S" in t.flag_str and "A" in t.flag_str
    assert transport_checksum("1.1.1.1", "2.2.2.2", ipv4.PROTO_TCP, seg) == 0
    assert tcp.OPT_MSS in t.option_dict()


def test_tcp_options_must_be_padded():
    import pytest
    with pytest.raises(ValueError):
        tcp.build("1.1.1.1", "2.2.2.2", 1, 2, options=b"\x01\x01\x01")  # len 3, not /4


def test_udp_roundtrip_and_zero_checksum_becomes_ffff():
    seg = udp.build("1.1.1.1", "2.2.2.2", 5353, 53, b"\x00\x01")
    u = udp.parse(seg)
    assert u.src_port == 5353 and u.dst_port == 53 and u.payload == b"\x00\x01"
    assert u.checksum != 0  # zero is replaced by 0xFFFF per RFC 768


def test_icmp_echo_checksum_and_parse():
    echo = icmp.build_echo(identifier=0x4242, seq=7)
    assert internet_checksum(echo) == 0
    msg = icmp.parse(echo)
    assert msg.type == icmp.ECHO_REQUEST and msg.code == 0


def test_icmp_unreachable_classification():
    assert icmp.classify_unreachable(icmp.CODE_PORT_UNREACH) == "closed"
    assert icmp.classify_unreachable(1) == "filtered"
    assert icmp.classify_unreachable(13) == "filtered"


def test_fragmentation_reassembles():
    payload = bytes(range(60))
    frags = ipv4.fragment("1.1.1.1", "2.2.2.2", ipv4.PROTO_TCP, payload, mtu=16, identification=0xABCD)
    assert len(frags) >= 4
    parsed = [ipv4.parse(f) for f in frags]
    assert all(p.identification == 0xABCD for p in parsed)
    # All but the last set More-Fragments.
    assert all(p.flags & ipv4.FLAG_MF for p in parsed[:-1])
    assert not (parsed[-1].flags & ipv4.FLAG_MF)
    reassembled = b"".join(p.payload for p in sorted(parsed, key=lambda z: z.frag_offset))
    assert reassembled == payload
