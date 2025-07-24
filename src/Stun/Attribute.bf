namespace BeefSturn.Stun;

using System;
using System.Collections;
using Beef_Net;

enum Transport : uint32
{
    TCP = 0x06000000,
    UDP = 0x11000000
}

enum IpFamily : uint8
{
    case V4 = 0x01;
    case V6 = 0x02;

    public static Result<IpFamily, StunError> TryFrom(uint8 val)
    {
        switch (val)
        {
            case 0x01: return .Ok(IpFamily.V4);
            case 0x02: return .Ok(IpFamily.V6);
            default: return .Err(StunError.InvalidInput);
        }
    }
}

/// [RFC3489]: https://datatracker.ietf.org/doc/html/rfc3489
///
/// The Address attribute indicates a reflexive transport address
/// of the client.  It consists of an 8-bit address family and a 16-bit
/// port, followed by a fixed-length value representing the IP address.
/// If the address family is IPv4, the address MUST be 32 bits.  If the
/// address family is IPv6, the address MUST be 128 bits.  All fields
/// must be in network byte order.
///
/// The format of the MAPPED-ADDRESS attribute is:
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0 0 0 0 0 0 0 0|    Family     |           Port                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                 Address (32 bits or 128 bits)                 |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Figure 5: Format of MAPPED-ADDRESS Attribute
///
/// The address family can take on the following values:
///
/// * 0x01:IPv4
/// * 0x02:IPv6
///
/// The first 8 bits of the MAPPED-ADDRESS MUST be set to 0 and MUST be
/// ignored by receivers.  These bits are present for aligning parameters
/// on natural 32-bit boundaries.
///
/// This attribute is used only by servers for achieving backwards
/// compatibility with [RFC3489] clients.
///
/// The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS
/// attribute, except that the reflexive transport address is obfuscated
/// through the XOR function.
///
/// The format of the XOR-MAPPED-ADDRESS is:
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0 0 0 0 0 0 0 0|    Family     |         X-Port                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                X-Address (Variable)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///          Figure 6: Format of XOR-MAPPED-ADDRESS Attribute
/// ```
///
/// The Family field represents the IP address family and is encoded
/// identically to the Family field in MAPPED-ADDRESS.
///
/// X-Port is computed by XOR'ing the mapped port with the most
/// significant 16 bits of the magic cookie.  If the IP address family is
/// IPv4, X-Address is computed by XOR'ing the mapped IP address with the
/// magic cookie.  If the IP address family is IPv6, X-Address is
/// computed by XOR'ing the mapped IP address with the concatenation of
/// the magic cookie and the 96-bit transaction ID.  In all cases, the
/// XOR operation works on its inputs in network byte order (that is, the
/// order they will be encoded in the message).
///
/// The rules for encoding and processing the first 8 bits of the
/// attribute's value, the rules for handling multiple occurrences of the
/// attribute, and the rules for processing address families are the same
/// as for MAPPED-ADDRESS.
///
/// Note: XOR-MAPPED-ADDRESS and MAPPED-ADDRESS differ only in their
/// encoding of the transport address.  The former encodes the transport
/// address by XOR'ing it with the magic cookie.  The latter encodes it
/// directly in binary.  [RFC3489] originally specified only MAPPED-
/// ADDRESS.  However, deployment experience found that some NATs rewrite
/// the 32-bit binary payloads containing the NAT's public IP address,
/// such as STUN's MAPPED-ADDRESS attribute, in the well-meaning but
/// misguided attempt to provide a generic Application Layer Gateway
/// (ALG) function.  Such behavior interferes with the operation of STUN
/// and also causes failure of STUN's message-integrity checking.
class Addr
{
    /// encoder SocketAddr as Bytes.
    public static void encode(SocketAddress addr, Span<uint8> token, List<uint8> bytes, bool is_xor)
    {
        bytes.Add(0);
        SocketAddress xor_addr = is_xor ? xor(addr, token) : addr;
        bool isIPv4 = xor_addr.Family == AF_INET;

        bytes.Add(isIPv4 ? IpFamily.V4.Underlying : IpFamily.V6.Underlying); // Note that stun protocol defines 1 as IPv4, 2 as IPv6

        uint16 port = 0;
        if (isIPv4)
        {
            port = xor_addr.u.IPv4.sin_port;
        }
        else
        {
            port = xor_addr.u.IPv6.sin6_port;
        }

        bytes.Add((uint8)(port >> 8));
        bytes.Add((uint8)(port & 0xFF));

        if (isIPv4)
        {
            bytes.AddRange(xor_addr.u.IPv4.sin_addr.s_bytes);
        }
        else
        {
            bytes.AddRange(xor_addr.u.IPv6.sin6_addr.u6_addr8);
        }
    }

    /// decoder Bytes as SocketAddr.
    public static Result<SocketAddress, StunError> decode(Span<uint8> packet, Span<uint8> token, bool is_xor)
    {
        if (packet.Length < 4)
        {
            return .Err(StunError.InvalidInput);
        }

        uint16 port = ((uint16)packet[3] << 8) | packet[2];

        if (IpFamily.TryFrom(packet[1]) case .Ok(let fam))
        {
            if (fam == IpFamily.V4 && from_bytes_v4(packet) case .Ok(let ip_addr))
            {
                SocketAddress dyn_addr = SocketAddress();
                dyn_addr.Family = AF_INET;
                dyn_addr.u = SocketAddress.USockAddr();
                dyn_addr.u.IPv4.sin_port = port;
                dyn_addr.u.IPv4.sin_addr = ip_addr;
                return .Ok(is_xor ? xor(dyn_addr, token) : dyn_addr);
            }
            else if (from_bytes_v6(packet) case .Ok(let ip_addr))
            {
                SocketAddress dyn_addr = SocketAddress();
                dyn_addr.Family = AF_INET6;
                dyn_addr.u = SocketAddress.USockAddr();
                dyn_addr.u.IPv6.sin6_port = port;
                dyn_addr.u.IPv6.sin6_addr = ip_addr;
                return .Ok(is_xor ? xor(dyn_addr, token) : dyn_addr);
            }
        }
        
        return .Err(StunError.InvalidInput);
    }
    
    public static Result<in_addr, StunError> from_bytes_v4(Span<uint8> packet)
    {
        if (packet.Length < 4)
        {
            return .Err(StunError.InvalidInput);
        }

        in_addr addr = in_addr();
        packet.Slice(4, 4).CopyTo(addr.s_bytes);
        return .Ok(addr);
    }

    public static Result<in6_addr, StunError> from_bytes_v6(Span<uint8> packet)
    {
        if (packet.Length < 4)
        {
            return .Err(StunError.InvalidInput);
        }

        in6_addr addr = in6_addr();
        packet.Slice(4, 16).CopyTo(addr.u6_addr8);
        return .Ok(addr);
    }

    public static SocketAddress xor(SocketAddress addr, Span<uint8> token)
    {
        SocketAddress naddr = SocketAddress();
        naddr.Family = addr.Family;
        naddr.u = SocketAddress.USockAddr();
        bool isIPv4 = addr.Family == AF_INET;
        uint16 port = 0;
        if (isIPv4)
        {
            port = addr.u.IPv4.sin_port;
        }
        else
        {
            port = addr.u.IPv6.sin6_port;
        }
        port = port ^ (0x2112A442 >> 16);
        if (isIPv4)
        {
            naddr.u.IPv4.sin_port = port;
            naddr.u.IPv4.sin_addr = xor_v4(addr.u.IPv4.sin_addr);
        }
        else
        {
            naddr.u.IPv6.sin6_port = port;
            naddr.u.IPv6.sin6_addr = xor_v6(addr.u.IPv6.sin6_addr, token);
        }
        return naddr;
    }

    public static in_addr xor_v4(in_addr addr)
    {
        in_addr naddr = addr;
        for (int i = 0; i < 4; i++)
        {
            naddr.s_bytes[i] ^= (uint8)((0x2112A442 >> (24 - i * 8)));
        }

        return naddr;
    }

    public static in6_addr xor_v6(in6_addr addr, Span<uint8> token)
    {
        in6_addr naddr = addr;
        int i = 0;
        for (; i < 4; i++)
        {
            naddr.u6_addr8[i] ^= (uint8)((0x2112A442 >> (24 - i * 8)));
        }

        for (; i < 16; i++)
        {
            naddr.u6_addr8[i] ^= token[i - 4];
        }

        return naddr;
    }
}

/// STUN Attributes Registry
///
/// [RFC8126]: https://datatracker.ietf.org/doc/html/rfc8126
/// [RFC5389]: https://datatracker.ietf.org/doc/html/rfc5389
/// [RFC8489]: https://datatracker.ietf.org/doc/html/rfc8489
///
/// A STUN attribute type is a hex number in the range 0x0000-0xFFFF.
/// STUN attribute types in the range 0x0000-0x7FFF are considered
/// comprehension-required; STUN attribute types in the range
/// 0x8000-0xFFFF are considered comprehension-optional.  A STUN agent
/// handles unknown comprehension-required and comprehension-optional
/// attributes differently.
///
/// STUN attribute types in the first half of the comprehension-required
/// range (0x0000-0x3FFF) and in the first half of the comprehension-
/// optional range (0x8000-0xBFFF) are assigned by IETF Review [RFC8126].
/// STUN attribute types in the second half of the comprehension-required
/// range (0x4000-0x7FFF) and in the second half of the comprehension-
/// optional range (0xC000-0xFFFF) are assigned by Expert Review
/// [RFC8126].  The responsibility of the expert is to verify that the
/// selected codepoint(s) are not in use and that the request is not for
/// an abnormally large number of codepoints.  Technical review of the
/// extension itself is outside the scope of the designated expert
/// responsibility.
///
/// IANA has updated the names for attributes 0x0002, 0x0004, 0x0005,
/// 0x0007, and 0x000B as well as updated the reference from [RFC5389] to
/// [RFC8489] for each the following STUN methods.
///
/// In addition, [RFC5389] introduced a mistake in the name of attribute
/// 0x0003; [RFC5389] called it CHANGE-ADDRESS when it was actually
/// previously called CHANGE-REQUEST.  Thus, IANA has updated the
/// description for 0x0003 to read "Reserved; was CHANGE-REQUEST prior to
/// [RFC5389]".
///
/// Comprehension-required range (0x0000-0x7FFF):
/// 0x0000: Reserved
/// 0x0001: MAPPED-ADDRESS
/// 0x0002: Reserved; was RESPONSE-ADDRESS prior to [RFC5389]
/// 0x0003: Reserved; was CHANGE-REQUEST prior to [RFC5389]
/// 0x0004: Reserved; was SOURCE-ADDRESS prior to [RFC5389]
/// 0x0005: Reserved; was CHANGED-ADDRESS prior to [RFC5389]
/// 0x0006: USERNAME
/// 0x0007: Reserved; was PASSWORD prior to [RFC5389]
/// 0x0008: MESSAGE-INTEGRITY
/// 0x0009: ERROR-CODE
/// 0x000A: UNKNOWN-ATTRIBUTES
/// 0x000B: Reserved; was REFLECTED-FROM prior to [RFC5389]
/// 0x0014: REALM
/// 0x0015: NONCE
/// 0x0020: XOR-MAPPED-ADDRESS
///
/// Comprehension-optional range (0x8000-0xFFFF)
/// 0x8022: SOFTWARE
///  0x8023: ALTERNATE-SERVER
/// 0x8028: FINGERPRINT
///
/// IANA has added the following attribute to the "STUN Attributes"
/// registry:
///
/// Comprehension-required range (0x0000-0x7FFF):
/// 0x001C: MESSAGE-INTEGRITY-SHA256
/// 0x001D: PASSWORD-ALGORITHM
///  0x001E: USERHASH
///
/// Comprehension-optional range (0x8000-0xFFFF)
/// 0x8002: PASSWORD-ALGORITHMS
/// 0x8003: ALTERNATE-DOMAIN
enum AttrKind : uint16
{
    Unknown = 0x0000,
    MappedAddress = 0x0001,
    UserName = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    ChannelNumber = 0x000C,
    Lifetime = 0x000D,
    XorPeerAddress = 0x0012,
    Data = 0x0013,
    Realm = 0x0014,
    Nonce = 0x0015,
    XorRelayedAddress = 0x0016,
    RequestedAddressFamily = 0x0017,
    EvenPort = 0x0018,
    RequestedTransport = 0x0019,
    DontFragment = 0x001A,
    AccessToken = 0x001B,
    MessageIntegritySha256 = 0x001C,
    PasswordAlgorithm = 0x001D,
    UserHash = 0x001E,
    XorMappedAddress = 0x0020,
    ReservationToken = 0x0022,
    Priority = 0x0024,
    UseCandidate = 0x0025,
    Padding = 0x0026,
    ResponsePort = 0x0027,
    ConnectionId = 0x002A,
    AdditionalAddressFamily = 0x8000,
    AddressErrorCode = 0x8001,
    PasswordAlgorithms = 0x8002,
    AlternateDomain = 0x8003,
    Icmp = 0x8004,
    Software = 0x8022,
    AlternateServer = 0x8023,
    TransactionTransmitCounter = 0x8025,
    CacheTimeout = 0x8027,
    Fingerprint = 0x8028,
    IceControlled = 0x8029,
    IceControlling = 0x802A,
    ResponseOrigin = 0x802B,
    OtherAddress = 0x802C,
    EcnCheck = 0x802D,
    ThirdPartyAuathorization = 0x802E,
    MobilityTicket = 0x8030
}

/// dyn stun/turn message attribute.
interface STAttribute
{
    /// current attribute type.
    public AttrKind KIND
    {
        get;
    }

    /// write the current attribute to the bytesfer.
    public void encode(List<uint8> bytes, Span<uint8> token);

    /// convert bytesfer to current attribute.
    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token);
}

/// [RFC8265]: https://datatracker.ietf.org/doc/html/rfc8265
/// [RFC5389]: https://datatracker.ietf.org/doc/html/rfc5389
/// [RFC3629]: https://datatracker.ietf.org/doc/html/rfc3629
///
/// The USERNAME attribute is used for message integrity.  It identifies
/// the username and password combination used in the message-integrity
/// check.
///
/// The value of USERNAME is a variable-length value containing the
/// authentication username.  It MUST contain a UTF-8-encoded [RFC3629]
/// sequence of fewer than 509 bytes and MUST have been processed using
/// the OpaqueString profile [RFC8265].  A compliant implementation MUST
/// be able to parse a UTF-8-encoded sequence of 763 or fewer octets to
/// be compatible with [RFC5389].
struct UserName : STAttribute, IDisposable
{
    public String username;

    public this()
    {
        username = new String();
    }

    public this(StringView setUname)
    {
        username = new String(setUname);
    }

    public void Dispose()
    {
        delete username;
    }

    public AttrKind KIND
    {
        get { return AttrKind.UserName; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        bytes.AddRange(Span<char8>(username.CStr(), username.Length).ToRawData());
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(UserName(StringView((char8*)bytes.Ptr, bytes.Length)));
    }
}

/// The DATA attribute is present in all Send and Data indications.  The
/// value portion of this attribute is variable length and consists of
/// the application data (that is, the data that would immediately follow
/// the UDP header if the data was been sent directly between the client
/// and the peer).  If the length of this attribute is not a multiple of
/// 4, then padding must be added after this attribute.
struct Data : STAttribute
{
    public Span<uint8> data;

    public this()
    {
        this = default;
    }

    public this(Span<uint8> setData)
    {
        data = setData;
    }

    public AttrKind KIND
    {
        get { return AttrKind.Data; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        bytes.AddRange(data);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(Data(bytes));
    }
}

/// [RFC3629]: https://datatracker.ietf.org/doc/html/rfc3629
/// [RFC3261]: https://datatracker.ietf.org/doc/html/rfc3261
/// [RFC8265]: https://datatracker.ietf.org/doc/html/rfc8265
///
/// The REALM attribute may be present in requests and responses.  It
/// contains text that meets the grammar for "realm-value" as described
/// in [RFC3261] but without the double quotes and their surrounding
/// whitespace.  That is, it is an unquoted realm-value (and is therefore
/// a sequence of qdtext or quoted-pair).  It MUST be a UTF-8-encoded
/// [RFC3629] sequence of fewer than 128 characters (which can be as long
/// as 509 bytes when encoding them and as long as 763 bytes when
/// decoding them) and MUST have been processed using the OpaqueString
/// profile [RFC8265].
///
/// Presence of the REALM attribute in a request indicates that long-term
/// credentials are being used for authentication.  Presence in certain
/// error responses indicates that the server wishes the client to use a
/// long-term credential in that realm for authentication.
struct Realm : STAttribute, IDisposable
{
    String realm;

    public this()
    {
        realm = new String();
    }

    public this(StringView setRealm)
    {
        realm = new String(setRealm);
    }

    public void Dispose()
    {
        delete realm;
    }

    public AttrKind KIND
    {
        get { return AttrKind.Realm; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        bytes.AddRange(Span<char8>(realm.CStr(), realm.Length).ToRawData());
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(Realm(StringView((char8*)bytes.Ptr, bytes.Length)));
    }
}

/// [RFC3261]: https://datatracker.ietf.org/doc/html/rfc3261
/// [RFC7616]: https://datatracker.ietf.org/doc/html/rfc7616
///
/// The NONCE attribute may be present in requests and responses.  It
/// contains a sequence of qdtext or quoted-pair, which are defined in
/// [RFC3261].  Note that this means that the NONCE attribute will not
/// contain the actual surrounding quote characters.  The NONCE attribute
/// MUST be fewer than 128 characters (which can be as long as 509 bytes
/// when encoding them and a long as 763 bytes when decoding them).  See
/// Section 5.4 of [RFC7616] for guidance on selection of nonce values in
/// a server.
struct Nonce : STAttribute, IDisposable
{
    String strVal;

    public this()
    {
        strVal = new String();
    }

    public this(StringView setStrVal)
    {
        strVal = new String(setStrVal);
    }

    public void Dispose()
    {
        delete strVal;
    }

    public AttrKind KIND
    {
        get { return AttrKind.Nonce; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        bytes.AddRange(Span<char8>(strVal.CStr(), strVal.Length).ToRawData());
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(Nonce(StringView((char8*)bytes.Ptr, bytes.Length)));
    }
}

/// [RFC3629]: https://datatracker.ietf.org/doc/html/rfc3629
///
/// The SOFTWARE attribute contains a textual description of the software
/// being used by the agent sending the message.  It is used by clients
/// and servers.  Its value SHOULD include manufacturer and version
/// number.  The attribute has no impact on operation of the protocol and
/// serves only as a tool for diagnostic and debugging purposes.  The
/// value of SOFTWARE is variable length.  It MUST be a UTF-8-encoded
/// [RFC3629] sequence of fewer than 128 characters (which can be as long
/// as 509 when encoding them and as long as 763 bytes when decoding
/// them).
struct Software : STAttribute, IDisposable
{
    String strVal;

    public this()
    {
        strVal = new String();
    }

    public this(StringView setStrVal)
    {
        strVal = new String(setStrVal);
    }

    public void Dispose()
    {
        delete strVal;
    }

    public AttrKind KIND
    {
        get { return AttrKind.Software; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        bytes.AddRange(Span<char8>(strVal.CStr(), strVal.Length).ToRawData());
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(Software(StringView((char8*)bytes.Ptr, bytes.Length)));
    }
}

/// [RFC2104]: https://datatracker.ietf.org/doc/html/rfc2104
/// [RFC5769]: https://datatracker.ietf.org/doc/html/rfc5769
///
/// The MESSAGE-INTEGRITY attribute contains an HMAC-SHA1 [RFC2104] of
/// the STUN message.  The MESSAGE-INTEGRITY attribute can be present in
/// any STUN message type.  Since it uses the SHA-1 hash, the HMAC will
/// be 20 bytes.
///
/// The key for the HMAC depends on which credential mechanism is in use.
/// Section 9.1.1 defines the key for the short-term credential
/// mechanism, and Section 9.2.2 defines the key for the long-term
/// credential mechanism.  Other credential mechanisms MUST define the
/// key that is used for the HMAC.
///
/// The text used as input to HMAC is the STUN message, up to and
/// including the attribute preceding the MESSAGE-INTEGRITY attribute.
/// The Length field of the STUN message header is adjusted to point to
/// the end of the MESSAGE-INTEGRITY attribute.  The value of the
/// MESSAGE-INTEGRITY attribute is set to a dummy value.
///
/// Once the computation is performed, the value of the MESSAGE-INTEGRITY
/// attribute is filled in, and the value of the length in the STUN
/// header is set to its correct value -- the length of the entire
/// message.  Similarly, when validating the MESSAGE-INTEGRITY, the
/// Length field in the STUN header must be adjusted to point to the end
/// of the MESSAGE-INTEGRITY attribute prior to calculating the HMAC over
/// the STUN message, up to and including the attribute preceding the
/// MESSAGE-INTEGRITY attribute.  Such adjustment is necessary when
/// attributes, such as FINGERPRINT and MESSAGE-INTEGRITY-SHA256, appear
/// after MESSAGE-INTEGRITY.  See also [RFC5769] for examples of such
/// calculations.
struct MessageIntegrity : STAttribute
{
    public Span<uint8> byteVal;

    public this()
    {
        this = default;
    }
    
    public this(Span<uint8> setByteVal)
    {
        byteVal = setByteVal;
    }

    public AttrKind KIND
    {
        get { return AttrKind.MessageIntegrity; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        bytes.AddRange(byteVal);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(MessageIntegrity(bytes));
    }
}

/// [RFC5389]: https://datatracker.ietf.org/doc/html/rfc5389
///
/// The XOR-PEER-ADDRESS specifies the address and port of the peer as
/// seen from the TURN server.  (For example, the peer's server-reflexive
/// transport address if the peer is behind a NAT.)  It is encoded in the
/// same way as XOR-MAPPED-ADDRESS [RFC5389].
struct XorPeerAddress : STAttribute
{
    public SocketAddress addr;

    public this()
    {
        addr = SocketAddress();
        addr.u = SocketAddress.USockAddr();
    }

    public this(SocketAddress setAddr)
    {
        addr = setAddr;
    }

    public AttrKind KIND
    {
        get { return AttrKind.XorPeerAddress; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        Addr.encode(addr, token, bytes, true);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(XorPeerAddress(Addr.decode(bytes, token, true)));
    }
}

/// [RFC5389]: https://datatracker.ietf.org/doc/html/rfc5389
///
/// The XOR-RELAYED-ADDRESS is present in Allocate responses.  It
/// specifies the address and port that the server allocated to the
/// client.  It is encoded in the same way as XOR-MAPPED-ADDRESS
/// [RFC5389].
struct XorRelayedAddress : STAttribute
{
    public SocketAddress addr;

    public this()
    {
        addr = SocketAddress();
        addr.u = SocketAddress.USockAddr();
    }

    public this(SocketAddress setAddr)
    {
        addr = setAddr;
    }

    public AttrKind KIND
    {
        get { return AttrKind.XorRelayedAddress; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        Addr.encode(addr, token, bytes, true);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(XorRelayedAddress(Addr.decode(bytes, token, true)));
    }
}

/// [RFC3489]: https://datatracker.ietf.org/doc/html/rfc3489
///
/// The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS
/// attribute, except that the reflexive transport address is obfuscated
/// through the XOR function.
///
/// The Family field represents the IP address family and is encoded
/// identically to the Family field in MAPPED-ADDRESS.
///
/// X-Port is computed by XOR'ing the mapped port with the most
/// significant 16 bits of the magic cookie.  If the IP address family is
/// IPv4, X-Address is computed by XOR'ing the mapped IP address with the
/// magic cookie.  If the IP address family is IPv6, X-Address is
/// computed by XOR'ing the mapped IP address with the concatenation of
/// the magic cookie and the 96-bit transaction ID.  In all cases, the
/// XOR operation works on its inputs in network byte order (that is, the
/// order they will be encoded in the message).
///
/// The rules for encoding and processing the first 8 bits of the
/// attribute's value, the rules for handling multiple occurrences of the
/// attribute, and the rules for processing address families are the same
/// as for MAPPED-ADDRESS.
///
/// Note: XOR-MAPPED-ADDRESS and MAPPED-ADDRESS differ only in their
/// encoding of the transport address.  The former encodes the transport
/// address by XOR'ing it with the magic cookie.  The latter encodes it
/// directly in binary.  [RFC3489] originally specified only MAPPED-
/// ADDRESS.  However, deployment experience found that some NATs rewrite
/// the 32-bit binary payloads containing the NAT's public IP address,
/// such as STUN's MAPPED-ADDRESS attribute, in the well-meaning but
/// misguided attempt to provide a generic Application Layer Gateway
/// (ALG) function.  Such behavior interferes with the operation of STUN
/// and also causes failure of STUN's message-integrity checking.
struct XorMappedAddress : STAttribute
{
    public SocketAddress addr;

    public this()
    {
        addr = SocketAddress();
        addr.u = SocketAddress.USockAddr();
    }

    public this(SocketAddress setAddr)
    {
        addr = setAddr;
    }

    public AttrKind KIND
    {
        get { return AttrKind.XorMappedAddress; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        Addr.encode(addr, token, bytes, true);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(XorMappedAddress(Addr.decode(bytes, token, true)));
    }
}

/// [RFC3489]: https://datatracker.ietf.org/doc/html/rfc3489
///
/// The MAPPED-ADDRESS attribute indicates a reflexive transport address
/// of the client.  It consists of an 8-bit address family and a 16-bit
/// port, followed by a fixed-length value representing the IP address.
/// If the address family is IPv4, the address MUST be 32 bits.  If the
/// address family is IPv6, the address MUST be 128 bits.  All fields
/// must be in network byte order.
///
/// The address family can take on the following values:
///
/// 0x01:IPv4
/// 0x02:IPv6
///
/// The first 8 bits of the MAPPED-ADDRESS MUST be set to 0 and MUST be
/// ignored by receivers.  These bits are present for aligning parameters
/// on natural 32-bit boundaries.
///
/// This attribute is used only by servers for achieving backwards
/// compatibility with [RFC3489] clients.
struct MappedAddress : STAttribute
{
    public SocketAddress addr;

    public this()
    {
        addr = SocketAddress();
        addr.u = SocketAddress.USockAddr();
    }

    public this(SocketAddress setAddr)
    {
        addr = setAddr;
    }

    public AttrKind KIND
    {
        get { return AttrKind.MappedAddress; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        Addr.encode(addr, token, bytes, false);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(MappedAddress(Addr.decode(bytes, token, false)));
    }
}

/// The RESPONSE-ORIGIN attribute is inserted by the server and indicates
/// the source IP address and port the response was sent from.  It is
/// useful for detecting double NAT configurations.  It is only present
/// in Binding Responses.
struct ResponseOrigin : STAttribute
{
    public SocketAddress addr;

    public this()
    {
        addr = SocketAddress();
        addr.u = SocketAddress.USockAddr();
    }

    public this(SocketAddress setAddr)
    {
        addr = setAddr;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.ResponseOrigin; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        Addr.encode(addr, token, bytes, false);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(ResponseOrigin(Addr.decode(bytes, token, false)));
    }
}

/// The following error codes, along with their recommended reason
/// phrases, are defined:
///
/// 300  Try Alternate: The client should contact an alternate server for
///      this request.  This error response MUST only be sent if the
///      request included either a USERNAME or USERHASH attribute and a
///      valid MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute;
///      otherwise, it MUST NOT be sent and error code 400 (Bad Request)
///      is suggested.  This error response MUST be protected with the
///      MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, and
///      receivers MUST validate the MESSAGE-INTEGRITY or MESSAGE-
///      INTEGRITY-SHA256 of this response before redirecting themselves
///      to an alternate server.
///      Note: Failure to generate and validate message integrity for a
///      300 response allows an on-path attacker to falsify a 300
///      response thus causing subsequent STUN messages to be sent to a
///      victim.
///      
/// 400  Bad Request: The request was malformed.  The client SHOULD NOT
///      retry the request without modification from the previous
///      attempt.  The server may not be able to generate a valid
///      MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 for this error, so
///      the client MUST NOT expect a valid MESSAGE-INTEGRITY or MESSAGE-
///      INTEGRITY-SHA256 attribute on this response.
///      
/// 401  Unauthenticated: The request did not contain the correct
///      credentials to proceed.  The client should retry the request
///      with proper credentials.
///      
/// 420  Unknown Attribute: The server received a STUN packet containing
///      a comprehension-required attribute that it did not understand.
///      The server MUST put this unknown attribute in the UNKNOWN-
///      ATTRIBUTE attribute of its error response.
///      
/// 438  Stale Nonce: The NONCE used by the client was no longer valid.
///      The client should retry, using the NONCE provided in the
///      response.
///      
/// 500  Server Error: The server has suffered a temporary error.  The
///      client should try again.
enum ErrorKind : uint16
{
    case TryAlternate = errno(300);
    case BadRequest = errno(400);
    case Unauthorized = errno(401);
    case Forbidden = errno(403);
    case UnknownAttribute = errno(420);
    case AllocationMismatch = errno(437);
    case StaleNonce = errno(438);
    case AddressFamilyNotSupported = errno(440);
    case WrongCredentials = errno(441);
    case UnsupportedTransportAddress = errno(442);
    case PeerAddressFamilyMismatch = errno(443);
    case AllocationQuotaReached = errno(486);
    case ServerError = errno(500);
    case InsufficientCapacity = errno(508);

    public static uint16 errno(uint16 code)
    {
        return ((code / 100) << 8) | (code % 100);
    }

    public void ToString(out String s)
    {
        switch (this)
        {
            case TryAlternate:
                s = "Try Alternate";
                break;
            case BadRequest:
                s = "Bad Request";
                break;
            case Unauthorized:
                s = "Unauthorized";
                break;
            case Forbidden:
                s = "Forbidden";
                break;
            case UnknownAttribute:
                s = "Unknown Attribute";
                break;
            case AllocationMismatch:
                s = "Allocation Mismatch";
                break;
            case StaleNonce:
                s = "Stale Nonce";
                break;
            case AddressFamilyNotSupported:
                s = "Address Family not Supported";
                break;
            case WrongCredentials:
                s = "Wrong Credentials";
                break;
            case UnsupportedTransportAddress:
                s = "Unsupported Transport Address";
                break;
            case PeerAddressFamilyMismatch:
                s = "Peer Address Family Mismatch";
                break;
            case AllocationQuotaReached:
                s = "Allocation Quota Reached";
                break;
            case ServerError:
                s = "Server Error";
                break; 
            case InsufficientCapacity:
                s = "Insufficient Capacity";
                break;
            default:
                s = "Unknown Error";
                break;
        }
    }
}

/// [RFC3629]: https://datatracker.ietf.org/doc/html/rfc3629
/// [RFC7231]: https://datatracker.ietf.org/doc/html/rfc7231
/// [RFC3261]: https://datatracker.ietf.org/doc/html/rfc3261
/// [RFC3629]: https://datatracker.ietf.org/doc/html/rfc3629
///
/// The ERROR-CODE attribute is used in error response messages.  It
/// contains a numeric error code value in the range of 300 to 699 plus a
/// textual reason phrase encoded in UTF-8 [RFC3629]; it is also
/// consistent in its code assignments and semantics with SIP [RFC3261]
/// and HTTP [RFC7231].  The reason phrase is meant for diagnostic
/// purposes and can be anything appropriate for the error code.
/// Recommended reason phrases for the defined error codes are included
/// in the IANA registry for error codes.  The reason phrase MUST be a
/// UTF-8-encoded [RFC3629] sequence of fewer than 128 characters (which
/// can be as long as 509 bytes when encoding them or 763 bytes when
/// decoding them).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Reserved, should be 0         |Class|     Number    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Reason Phrase (variable)                                ..
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///              Figure 7: Format of ERROR-CODE Attribute
/// ```
///
/// To facilitate processing, the class of the error code (the hundreds
/// digit) is encoded separately from the rest of the code, as shown in
/// Figure 7.
///
/// The Reserved bits SHOULD be 0 and are for alignment on 32-bit
/// boundaries.  Receivers MUST ignore these bits.  The Class represents
/// the hundreds digit of the error code.  The value MUST be between 3
/// and 6.  The Number represents the binary encoding of the error code
/// modulo 100, and its value MUST be between 0 and 99.
struct StunRespError
{
    uint16 code;
    StringView message;

    public this()
    {
        this = default;
    }

    public this(uint16 setCode, StringView setMessage)
    {
        code = setCode;
        message = setMessage;
    }

    /// create error from error type.
    public static StunRespError from(ErrorKind value)
    {
        String serror = scope String();
        value.ToString(serror);
        return StunRespError(value.Underlying, serror);
    }

    /// encode the error type as bytes.
    public void encode(List<uint8> bytes)
    {
        bytes.Add(0);
        bytes.Add(0);
        bytes.Add((uint8)(code >> 8));
        bytes.Add((uint8)(code & 0xFF));
        bytes.AddRange(message.ToRawData());
    }

    public static Result<StunRespError, StunError> try_from(Span<uint8> packet)
    {
        if (packet.Length < 4)
        {
            return .Err(StunError.InvalidInput);
        }

        if (packet[0] != 0 || packet[1] != 0)
        {
            return .Err(StunError.InvalidInput);
        }

        return .Ok(StunRespError((uint16)packet[3] << 8 | packet[2],
            StringView((char8*)packet.Ptr + 4, packet.Length - 4)));
    }

    public bool eq(StunRespError other)
    {
        return code == other.code;
    }

    public static bool operator==(StunRespError lhs, StunRespError rhs)
    {
        return lhs.eq(rhs);
    }
}

/// [RFC7231]: https://datatracker.ietf.org/doc/html/rfc7231
/// [RFC3261]: https://datatracker.ietf.org/doc/html/rfc3261
/// [RFC3629]: https://datatracker.ietf.org/doc/html/rfc3629
///
/// The ERROR-CODE attribute is used in error response messages.  It
/// contains a numeric error code value in the range of 300 to 699 plus a
/// textual reason phrase encoded in UTF-8 [RFC3629]; it is also
/// consistent in its code assignments and semantics with SIP [RFC3261]
/// and HTTP [RFC7231].  The reason phrase is meant for diagnostic
/// purposes and can be anything appropriate for the error code.
/// Recommended reason phrases for the defined error codes are included
/// in the IANA registry for error codes.  The reason phrase MUST be a
/// UTF-8-encoded [RFC3629] sequence of fewer than 128 characters (which
/// can be as long as 509 bytes when encoding them or 763 bytes when
/// decoding them).
struct ErrorCode : STAttribute
{
    public StunRespError error;

    public this()
    {
        error = StunRespError();
    }

    public this(StunRespError setError)
    {
        error = setError;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.ErrorCode; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        error.encode(bytes);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(ErrorCode(StunRespError.try_from(bytes)));
    }
}

/// The LIFETIME attribute represents the duration for which the server
/// will maintain an allocation in the absence of a refresh.  The value
/// portion of this attribute is 4-bytes long and consists of a 32-bit
/// unsigned integral value representing the number of seconds remaining
/// until expiration.
struct Lifetime : STAttribute
{
    public uint32 lifetime;

    public this()
    {
        lifetime = 0;
    }

    public this(uint32 setLifetime)
    {
        lifetime = setLifetime;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.Lifetime; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // Make 4 uint to respresent an uint32
        bytes.Add((uint8)(lifetime >> 24));
        bytes.Add((uint8)(lifetime >> 16));
        bytes.Add((uint8)(lifetime >> 8));
        bytes.Add((uint8)(lifetime & 0xFF));
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(Lifetime((uint32)bytes[3] << 24 | (uint32)bytes[2] << 16 | (uint16)bytes[1] << 8 | bytes[0]));
    }
}

/// This attribute is used by the client to request a specific transport
/// protocol for the allocated transport address.
///
/// The Protocol field specifies the desired protocol.  The codepoints
/// used in this field are taken from those allowed in the Protocol field
/// in the IPv4 header and the NextHeader field in the IPv6 header
/// [Protocol-Numbers].  This specification only allows the use of
/// codepoint 17 (User Datagram Protocol).
///
/// The RFFU field MUST be set to zero on transmission and MUST be
/// ignored on reception.  It is reserved for future uses.
struct RequestedTransport : STAttribute
{
    Transport transport;

    public this()
    {
        transport = Transport.UDP;
    }

    public this(Transport setTransport)
    {
        transport = setTransport;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.RequestedTransport; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // Make 4 uint to respresent an uint32
        bytes.Add((uint8)(transport.Underlying >> 24));
        bytes.Add(0);
        bytes.Add(0);
        bytes.Add(0);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        uint32 decodedValue = (uint32)bytes[0];
        if (decodedValue == Transport.UDP.Underlying)
        {
            return .Ok(Lifetime(Transport.UDP.Underlying));
        }
        else if (decodedValue == Transport.TCP.Underlying)
        {
            return .Ok(Lifetime(Transport.TCP.Underlying));
        }

        return .Err(StunError.InvalidInput);
    }
}

/// [RFC1952]: https://datatracker.ietf.org/doc/html/rfc1952
///
/// The FINGERPRINT attribute MAY be present in all STUN messages.
///
/// The value of the attribute is computed as the CRC-32 of the STUN
/// message up to (but excluding) the FINGERPRINT attribute itself,
/// XOR'ed with the 32-bit value 0x5354554e.  (The XOR operation ensures
/// that the FINGERPRINT test will not report a false positive on a
/// packet containing a CRC-32 generated by an application protocol.)
///
/// The 32-bit CRC is the one defined in ITU V.42, which has a generator
/// polynomial of x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 +
/// x^7 + x^5 + x^4 + x^2 + x + 1.  See the sample code for the CRC-32 in
/// Section 8 of [RFC1952].
///
/// When present, the FINGERPRINT attribute MUST be the last attribute in
/// the message and thus will appear after MESSAGE-INTEGRITY and MESSAGE-
/// INTEGRITY-SHA256.
///
/// The FINGERPRINT attribute can aid in distinguishing STUN packets from
/// packets of other protocols.  See Section 7.
///
/// As with MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256, the CRC used
/// in the FINGERPRINT attribute covers the Length field from the STUN
/// message header.  Therefore, prior to computation of the CRC, this
/// value must be correct and include the CRC attribute as part of the
/// message length.  When using the FINGERPRINT attribute in a message,
/// the attribute is first placed into the message with a dummy value;
/// then, the CRC is computed, and the value of the attribute is updated.
/// If the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute is
/// also present, then it must be present with the correct message-
/// integrity value before the CRC is computed, since the CRC is done
/// over the value of the MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256
/// attributes as well.
struct Fingerprint : STAttribute
{
    public uint32 value;

    public this()
    {
        value = 0;
    }

    public this(uint32 setValue)
    {
        value = setValue;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.Fingerprint; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // Make 4 uint to respresent an uint32
        bytes.Add((uint8)(value >> 24));
        bytes.Add((uint8)(value >> 16));
        bytes.Add((uint8)(value >> 8));
        bytes.Add((uint8)(value & 0xFF));
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(Fingerprint((uint32)bytes[3] << 24 | (uint32)bytes[2] << 16 | (uint16)bytes[1] << 8 | bytes[0]));
    }
}

/// The CHANNEL-NUMBER attribute contains the number of the channel.  The
/// value portion of this attribute is 4 bytes long and consists of a
/// 16-bit unsigned integer followed by a two-octet RFFU (Reserved For
/// Future Use) field, which MUST be set to 0 on transmission and MUST be
/// ignored on reception.
struct ChannelNumber : STAttribute
{
    public uint16 number;

    public this()
    {
        number = 0;
    }

    public this(uint16 setNumber)
    {
        number = setNumber;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.ChannelNumber; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // Make 4 uint to respresent an uint32
        bytes.Add((uint8)(number >> 8));
        bytes.Add((uint8)(number & 0xFF));
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(ChannelNumber((uint16)bytes[1] << 8 | bytes[0]));
    }
}

/// The ICE-CONTROLLING attribute is present in a Binding request.  The
/// attribute indicates that the client believes it is currently in the
/// controlling role.  The content of the attribute is a 64-bit unsigned
/// integer in network byte order, which contains a random number.  As
/// for the ICE-CONTROLLED attribute, the number is used for solving role
/// conflicts.  An agent MUST use the same number for all Binding
/// requests, for all streams, within an ICE session, unless it has
/// received a 487 response, in which case it MUST change the number.  
/// The agent MAY change the number when an ICE restart occurs.
struct IceControlling : STAttribute
{
    public uint64 value;

    public this()
    {
        value = 0;
    }

    public this(uint64 setValue)
    {
        value = setValue;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.IceControlling; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // Make 8 uint to respresent an uint64
        bytes.Add((uint8)(value >> 56));
        bytes.Add((uint8)(value >> 48));
        bytes.Add((uint8)(value >> 40));
        bytes.Add((uint8)(value >> 32));
        bytes.Add((uint8)(value >> 24));
        bytes.Add((uint8)(value >> 16));
        bytes.Add((uint8)(value >> 8));
        bytes.Add((uint8)(value & 0xFF));
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(IceControlling((uint64)bytes[7] << 56 | (uint64)bytes[6] << 48 |
            (uint64)bytes[5] << 40 | (uint64)bytes[4] << 32 |
            (uint32)bytes[3] << 24 | (uint32)bytes[2] << 16 |
            (uint16)bytes[1] << 8 | bytes[0]));
    }
}

/// The USE-CANDIDATE attribute indicates that the candidate pair
/// resulting from this check will be used for transmission of data.  The
/// attribute has no content (the Length field of the attribute is zero);
/// it serves as a flag.  It has an attribute value of 0x0025..
struct UseCandidate : STAttribute
{
    public this() {}

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.UseCandidate; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // No content, just a flag
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(UseCandidate());
    }
}

/// The ICE-CONTROLLED attribute is present in a Binding request.  The
/// attribute indicates that the client believes it is currently in the
/// controlled role.  The content of the attribute is a 64-bit unsigned
/// integer in network byte order, which contains a random number.  The
/// number is used for solving role conflicts, when it is referred to as
/// the "tiebreaker value".  An ICE agent MUST use the same number for
/// all Binding requests, for all streams, within an ICE session, unless
/// it has received a 487 response, in which case it MUST change the
/// number. The agent MAY change the number when an ICE restart occurs.
struct IceControlled : STAttribute
{
    public uint64 value;

    public this()
    {
        value = 0;
    }

    public this(uint64 setValue)
    {
        value = setValue;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.IceControlled; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // Make 8 uint to respresent an uint64
        bytes.Add((uint8)(value >> 56));
        bytes.Add((uint8)(value >> 48));
        bytes.Add((uint8)(value >> 40));
        bytes.Add((uint8)(value >> 32));
        bytes.Add((uint8)(value >> 24));
        bytes.Add((uint8)(value >> 16));
        bytes.Add((uint8)(value >> 8));
        bytes.Add((uint8)(value & 0xFF));
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(IceControlled((uint64)bytes[7] << 56 | (uint64)bytes[6] << 48 |
            (uint64)bytes[5] << 40 | (uint64)bytes[4] << 32 |
            (uint32)bytes[3] << 24 | (uint32)bytes[2] << 16 |
            (uint16)bytes[1] << 8 | bytes[0]));
    }
}

/// The PRIORITY attribute indicates the priority that is to be
/// associated with a peer-reflexive candidate, if one will be discovered
/// by this check.  It is a 32-bit unsigned integer and has an attribute
/// value of 0x0024.
struct Priority : STAttribute
{
    public uint32 value;

    public this()
    {
        value = 0;
    }

    public this(uint32 setValue)
    {
        value = setValue;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.Priority; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // Make 4 uint to respresent an uint32
        bytes.Add((uint8)(value >> 24));
        bytes.Add((uint8)(value >> 16));
        bytes.Add((uint8)(value >> 8));
        bytes.Add((uint8)(value & 0xFF));
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(Priority((uint32)bytes[3] << 24 | (uint32)bytes[2] << 16 | (uint16)bytes[1] << 8 | bytes[0]));
    }
}

/// The RESERVATION-TOKEN attribute contains a token that uniquely identifies a
/// relayed transport address being held in reserve by the server. The server
/// includes this attribute in a success response to tell the client about the
/// token, and the client includes this attribute in a subsequent Allocate
/// request to request the server use that relayed transport address for the
/// allocation.
///
/// The attribute value is 8 bytes and contains the token value.
struct ReservationToken : STAttribute
{
    public uint64 value;

    public this()
    {
        value = 0;
    }

    public this(uint64 setValue)
    {
        value = setValue;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.ReservationToken; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // Make 8 uint to respresent an uint64
        bytes.Add((uint8)(value >> 56));
        bytes.Add((uint8)(value >> 48));
        bytes.Add((uint8)(value >> 40));
        bytes.Add((uint8)(value >> 32));
        bytes.Add((uint8)(value >> 24));
        bytes.Add((uint8)(value >> 16));
        bytes.Add((uint8)(value >> 8));
        bytes.Add((uint8)(value & 0xFF));
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(ReservationToken((uint64)bytes[7] << 56 | (uint64)bytes[6] << 48 |
            (uint64)bytes[5] << 40 | (uint64)bytes[4] << 32 |
            (uint32)bytes[3] << 24 | (uint32)bytes[2] << 16 |
            (uint16)bytes[1] << 8 | bytes[0]));
    }
}

/// This attribute allows the client to request that the port in the relayed
/// transport address be even, and (optionally) that the server reserve the
/// next-higher port number.  The value portion of this attribute is 1 byte
/// long.
struct EvenPort : STAttribute
{
    public bool value;

    public this()
    {
        value = false;
    }

    public this(bool setValue)
    {
        value = setValue;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.EvenPort; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        bytes.Add(value ? 128 : 0);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(EvenPort(bytes[0] == 128));
    }
}

/// The REQUESTED-ADDRESS-FAMILY attribute is used by clients to request the
/// allocation of a specific address type from a server.  The following is the
/// format of the REQUESTED-ADDRESS-FAMILY attribute. Note that TURN attributes
/// are TLV (Type-Length-Value) encoded, with a 16-bit type, a 16-bit length,
/// and a variable-length value.
struct RequestedAddressFamily : STAttribute
{
    public IpFamily ipFam;

    public this()
    {
        ipFam = IpFamily.V4;
    }

    public this(IpFamily setValue)
    {
        ipFam = setValue;
    }

    public AttrKind KIND
    {
        get { return AttrKind.RequestedAddressFamily; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        bytes.Add(ipFam.Underlying);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        if (IpFamily.TryFrom(bytes[0]) case .Ok(let family))
        {
            return .Ok(RequestedAddressFamily(family));
        }
        else
        {
            return .Err(StunError.InvalidInput);
        }
    }
}

/// This attribute is used by clients to request the allocation of an IPv4 and
/// IPv6 address type from a server. It is encoded in the same way as the
/// REQUESTED-ADDRESS-FAMILY attribute; The ADDITIONAL-ADDRESS-FAMILY attribute
/// MAY be present in the Allocate request. The attribute value of 0x02 (IPv6
/// address) is the only valid value in Allocate request.
struct AdditionalAddressFamily : STAttribute
{
    public IpFamily ipFam;

    public this()
    {
        ipFam = IpFamily.V4;
    }

    public this(IpFamily setValue)
    {
        ipFam = setValue;
    }

    public AttrKind KIND
    {
        get { return AttrKind.AdditionalAddressFamily; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        bytes.Add(ipFam.Underlying);
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        if (IpFamily.TryFrom(bytes[0]) case .Ok(let family))
        {
            return .Ok(AdditionalAddressFamily(family));
        }
        else
        {
            return .Err(StunError.InvalidInput);
        }
    }
}

/// This attribute is used by the client to request that the server set the DF
/// (Don't Fragment) bit in the IP header when relaying the application data
/// onward to the peer and for determining the server capability in Allocate
/// requests. This attribute has no value part, and thus, the attribute length
/// field is 0.
struct DontFragment : STAttribute
{
    public this()
    {
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.DontFragment; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // No content, just a flag
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        return .Ok(DontFragment());
    }
}

/// The access token is issued by the authorization server.  OAuth 2.0 does not
/// impose any limitation on the length of the access token but if path MTU is
/// unknown, then STUN messages over IPv4 would need to be less than 548 bytes
/// (Section 7.1 of [RFC5389]).  The access token length needs to be restricted
/// to fit within the maximum STUN message size.  Note that the self-contained
/// token is opaque to the client, and the client MUST NOT examine the token.
/// The ACCESS-TOKEN attribute is a comprehension-required attribute (see
/// Section 15 from [RFC5389]).
struct AccessToken : STAttribute, IDisposable
{
    public String nonce;
    public String mac_key;
    public uint64 timestamp;
    public uint lifetime;

    public this()
    {
        nonce = new String();
        mac_key = new String();
        timestamp = 0;
        lifetime = 0;
    }

    public this(StringView setNonce, StringView setMacKey, uint64 setTimestamp, uint setLifetime)
    {
        nonce = new String(setNonce);
        mac_key = new String(setMacKey);
        timestamp = setTimestamp;
        lifetime = setLifetime;
    }

    public void Dispose()
    {
        delete nonce;
        delete mac_key;
    }

    public AttrKind KIND
    {
        get { return AttrKind.AccessToken; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // nonce_length:  Length of the nonce field.  The length of nonce for AEAD
        // algorithms is explained in [RFC5116].
        bytes.Add((uint8)(nonce.Length >> 8));
        bytes.Add((uint8)(nonce.Length & 0xFF));
        bytes.AddRange(Span<char8>(nonce.CStr(), nonce.Length).ToRawData());

        // key_length:  Length of the session key in octets.  The key length of 160 bits
        // MUST be supported (i.e., only the 160-bit key is used by HMAC-SHA-1 for
        // message integrity of STUN messages).  The key length facilitates the hash
        // agility plan discussed in Section 16.3 of [RFC5389].
        bytes.Add((uint8)(mac_key.Length >> 8));
        bytes.Add((uint8)(mac_key.Length & 0xFF));
        bytes.AddRange(Span<char8>(mac_key.CStr(), mac_key.Length).ToRawData());

        // timestamp:  64-bit unsigned integer field containing a timestamp.
        bytes.Add((uint8)(timestamp >> 56));
        bytes.Add((uint8)(timestamp >> 48));
        bytes.Add((uint8)(timestamp >> 40));
        bytes.Add((uint8)(timestamp >> 32));
        bytes.Add((uint8)(timestamp >> 24));
        bytes.Add((uint8)(timestamp >> 16));
        bytes.Add((uint8)(timestamp >> 8));
        bytes.Add((uint8)(timestamp & 0xFF));

        // lifetime:  The lifetime of the access token, in seconds.
        bytes.Add((uint8)(lifetime >> 24));
        bytes.Add((uint8)(lifetime >> 16));
        bytes.Add((uint8)(lifetime >> 8));
        bytes.Add((uint8)(lifetime & 0xFF));
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        // nonce_length:  Length of the nonce field.  The length of nonce for AEAD
        // algorithms is explained in [RFC5116].
        int offset = 0;
        uint16 nonce_length = (uint16)bytes[offset + 1] << 8 | bytes[offset];
        if (nonce_length >= bytes.Length)
        {
            return .Err(StunError.InvalidInput);
        }

        offset = 2;
        // Nonce: Nonce (N) formation is explained in Section 3.2 of [RFC5116].
        String nnonce = scope String((char8*)bytes.Slice(offset, nonce_length).Ptr);
        offset += nonce_length;

        // key_length:  Length of the session key in octets.  The key length of 160 bits
        // MUST be supported (i.e., only the 160-bit key is used by HMAC-SHA-1 for
        // message integrity of STUN messages).  The key length facilitates the hash
        // agility plan discussed in Section 16.3 of [RFC5389].
        uint16 key_length = (uint16)bytes[offset + 1] << 8 | bytes[offset];
        if (key_length >= bytes.Length)
        {
            return .Err(StunError.InvalidInput);
        }
        offset += 2;

        // mac_key:  The session key generated by the authorization server.
        String nmac_key = scope String((char8*)bytes.Slice(offset, key_length).Ptr);
        
        offset += key_length;
        if (bytes.Length < offset + 12)
        {
            return .Err(StunError.InvalidInput);
        }

        // timestamp:  64-bit unsigned integer field containing a timestamp. The value indicates the time since
        // January 1, 1970, 00:00 UTC, by using a fixed-point format.  In this format, the integer number of seconds
        // is contained in the first 48 bits of the field, and the remaining 16 bits indicate the number of 1/64000
        // fractions of a second (Native format - Unix).
        uint64 timestamp = (uint64)bytes[offset + 7] << 56 |
            (uint64)bytes[offset + 6] << 48 |
            (uint64)bytes[offset + 5] << 40 |
            (uint64)bytes[offset + 4] << 32 |
            (uint32)bytes[offset + 3] << 24 |
            (uint32)bytes[offset + 2] << 16 |
            (uint16)bytes[offset + 1] << 8 |
            (uint8)bytes[offset];

        offset += 8;

        // lifetime:  The lifetime of the access token, in seconds.  For example, the value 3600 indicates one hour.
        // The lifetime value MUST be greater than or equal to the 'expires_in' parameter defined in Section 4.2.2
        // of [RFC6749], otherwise the resource server could revoke the token, but the client would assume that the
        // token has not expired and would not refresh the token.
        uint32 lifetime = (uint32)bytes[offset + 3] << 24 |
            (uint32)bytes[offset + 2] << 16 |
            (uint16)bytes[offset + 1] << 8 |
            (uint8)bytes[offset];

        return .Ok(AccessToken(nnonce, nmac_key, timestamp, lifetime));
    }
}

/// This attribute is used by the STUN server to inform the client that
/// it supports third-party authorization.  This attribute value contains
/// the STUN server name.  The authorization server may have tie ups with
/// multiple STUN servers and vice versa, so the client MUST provide the
/// STUN server name to the authorization server so that it can select
/// the appropriate keying material to generate the self-contained token.
/// If the authorization server does not have tie up with the STUN
/// server, then it returns an error to the client.  If the client does
/// not support or is not capable of doing third-party authorization,
/// then it defaults to first-party authentication.  The
/// THIRD-PARTY-AUTHORIZATION attribute is a comprehension-optional
/// attribute (see Section 15 from [RFC5389]).  If the client is able to
/// comprehend THIRD-PARTY-AUTHORIZATION, it MUST ensure that third-party
/// authorization takes precedence over first-party authentication (as
/// explained in Section 10 of [RFC5389]).
struct ThirdPartyAuathorization : STAttribute, IDisposable
{
    public String server_name;

    public this()
    {
        server_name = new String();
    }

    public this(StringView setServerName)
    {
        server_name = new String(setServerName);
    }

    public void Dispose()
    {
        delete server_name;
    }

    /// The KIND of this attribute.
    public AttrKind KIND
    {
        get { return AttrKind.ThirdPartyAuathorization; }
    }

    public void encode(List<uint8> bytes, Span<uint8> token)
    {
        // Encode the server name as UTF-8
        bytes.AddRange(Span<char8>(server_name.CStr(), server_name.Length).ToRawData());
    }

    public Result<STAttribute, STError> decode(Span<uint8> bytes, Span<uint8> token)
    {
        // Decode the server name from UTF-8
        String serverName = scope String((char8*)bytes.Ptr, bytes.Length);
        return .Ok(ThirdPartyAuathorization(serverName));
    }
}

