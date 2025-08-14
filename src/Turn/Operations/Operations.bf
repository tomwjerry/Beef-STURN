namespace BeefSturn.Turn.Operations;

using System;
using System.Collections;
using Beef_Net;
using BeefSturn;
using BeefSturn.Stun;

enum ResponseMethod
{
    case Stun(Method.StunMethod sm);
    case ChannelData;
}

/// The context of the service.
///
/// A service corresponds to a Net Endpoint, different sockets have different
/// addresses and so on, but other things are basically the same.
struct ServiceContext : IDisposable
{
    public StringView realm;
    public StringView software;
    public Sessions sessions;
    public SocketAddress endpoint;
    public SocketAddress sainterface;
    public List<SocketAddress> interfaces;
    public Observer observer;

    public this()
    {
        this = default;
        interfaces = new List<SocketAddress>();
        observer = new Observer(Config(), Statistics());
        sessions = new Sessions(observer);
    }

    public this(Span<SocketAddress> interfaces, Observer observer, Sessions sessions)
    {
        this = default;
        this.interfaces = new List<SocketAddress>(interfaces);
        this.observer = new Observer(observer);
        this.sessions = new Sessions(sessions);
    }

    public void Dispose()
    {
        delete interfaces;
        delete observer;
        delete sessions;
    }
}

/// The request of the service.
struct Request : IDisposable
{
    public SessionAddr address;
    public ByteList bytes;
    public ServiceContext service;
    public MessageRef message;
    public ChannelData chanData;

    public this()
    {
        this = default;
        bytes = new ByteList();
    }

    public this(SessionAddr addr, Span<uint8> btlist, ServiceContext sc, MessageRef msg)
    {
        address = addr;
        bytes = new ByteList();
        bytes.Set(btlist);
        service = sc;
        message = msg;
        chanData = ChannelData();
    }

    public this(SessionAddr addr, Span<uint8> btlist, ServiceContext sc, ChannelData chanDt)
    {
        address = addr;
        bytes = new ByteList();
        bytes.Set(btlist);
        service = sc;
        message = MessageRef();
        chanData = chanDt;
    }

    public void Dispose()
    {
        delete bytes;
        message.Dispose();
        service.Dispose();
    }

    public bool verify_ip(SocketAddress address)
    {
        service.interfaces.FindIndex(scope (item) =>
        {
            if (address.Family == AF_INET)
            {
                return address.u.IPv4.sin_addr.s_addr == item.u.IPv4.sin_addr.s_addr;
            }
            else
            {
                return address.u.IPv6.sin6_addr.u6_addr32 == item.u.IPv6.sin6_addr.u6_addr32;
            }
        });

        return false;
    }

    /// The key for the HMAC depends on whether long-term or short-term
    /// credentials are in use.  For long-term credentials, the key is 16
    /// bytes:
    ///
    /// key = MD5(username ":" realm ":" SASLprep(password))
    ///
    /// That is, the 16-byte key is formed by taking the MD5 hash of the
    /// result of concatenating the following five fields: (1) the username,
    /// with any quotes and trailing nulls removed, as taken from the
    /// USERNAME attribute (in which case SASLprep has already been applied);
    /// (2) a single colon; (3) the realm, with any quotes and trailing nulls
    /// removed; (4) a single colon; and (5) the password, with any trailing
    /// nulls removed and after processing using SASLprep.  For example, if
    /// the username was 'user', the realm was 'realm', and the password was
    /// 'pass', then the 16-byte HMAC key would be the result of performing
    /// an MD5 hash on the string 'user:realm:pass', the resulting hash being
    /// 0x8493fbc53ba582fb4c044c456bdc40eb.
    ///
    /// For short-term credentials:
    ///
    /// key = SASLprep(password)
    ///
    /// where MD5 is defined in RFC 1321 [RFC1321] and SASLprep() is defined
    /// in RFC 4013 [RFC4013].
    ///
    /// The structure of the key when used with long-term credentials
    /// facilitates deployment in systems that also utilize SIP.  Typically,
    /// SIP systems utilizing SIP's digest authentication mechanism do not
    /// actually store the password in the database.  Rather, they store a
    /// value called H(A1), which is equal to the key defined above.
    ///
    /// Based on the rules above, the hash used to construct MESSAGE-
    /// INTEGRITY includes the length field from the STUN message header.
    /// Prior to performing the hash, the MESSAGE-INTEGRITY attribute MUST be
    /// inserted into the message (with dummy content).  The length MUST then
    /// be set to point to the length of the message up to, and including,
    /// the MESSAGE-INTEGRITY attribute itself, but excluding any attributes
    /// after it.  Once the computation is performed, the value of the
    /// MESSAGE-INTEGRITY attribute can be filled in, and the value of the
    /// length in the STUN header can be set to its correct value -- the
    /// length of the entire message.  Similarly, when validating the
    /// MESSAGE-INTEGRITY, the length field should be adjusted to point to
    /// the end of the MESSAGE-INTEGRITY attribute prior to calculating the
    /// HMAC.  Such adjustment is necessary when attributes, such as
    /// FINGERPRINT, appear after MESSAGE-INTEGRITY.
    public Result<(StringView, uint8[16])> auth()
    {
        let username = message.getAttr<UserName>();
        StringView usernameStr;
        if (username case .Ok(let unameMsg))
        {
            usernameStr = ((UserName)unameMsg).username;
        }
        else
        {
            return .Err;
        }
        uint8[16] integrity = service.sessions.get_integrity(address, usernameStr, service.realm);

        // if nonce is not empty, check nonce
        if (message.getAttr<Nonce>() case .Ok(let nonce))
        {
            if (service.sessions.get_nonce(address).0 != ((Nonce)nonce).strVal)
            {
                return .Err;
            }
        }

        if (message.integrity(Digest(integrity)) case .Err)
        {
            return .Err;
        }
        return .Ok((usernameStr, integrity));
    }
}

/// The response of the service.
struct Response
{
    public Span<uint8> bytes;
    public ResponseMethod method;
    public SocketAddress? relay;
    public SocketAddress? endpoint;

    public this()
    {
        bytes = Span<uint8>();
        method = ResponseMethod();
        relay = null;
        endpoint = null;
    }
}

/// process udp message and return message + address
struct Operationer : IDisposable
{
    public ServiceContext service;
    public SessionAddr address;
    public Decoder decoder;
    public ByteList bytes;

    public this(ServiceContext service)
    {
        this.address = SessionAddr() {
            address = SocketAddress()
            {
                Family = AF_INET,
                u = (SocketAddress.USockAddr()
                {
                    IPv4 = sockaddr_in()
                    {
                        sin_port = 0,
                        sin_addr = in_addr() { s_bytes = uint8[4](0, 0, 0, 0) }
                    }
                })
            },
            sainterface = service.sainterface
        };

        bytes = new ByteList();
        bytes.EnsureCapacity(4096, true);
        
        this.service = service;
    }

    public void Dispose()
    {
        delete bytes;
    }

    /// process udp data
    ///
    /// receive STUN encoded Bytes,
    /// and return any Bytes that can be responded to and the target address.
    /// Note: unknown message is not process.
    ///
    /// In a typical configuration, a TURN client is connected to a private
    /// network [RFC1918] and, through one or more NATs, to the public
    /// Internet.  On the public Internet is a TURN server.  Elsewhere in the
    /// Internet are one or more peers with which the TURN client wishes to
    /// communicate.  These peers may or may not be behind one or more NATs.
    /// The client uses the server as a relay to send packets to these peers
    /// and to receive packets from these peers.
    ///
    /// ```text
    ///                                     Peer A
    ///                                     Server-Reflexive    +---------+
    ///                                    Transport Address   |         |
    ///                                      192.0.2.150:32102   |         |
    ///                                        |              /|         |
    ///                       TURN              |            / ^|  Peer A |
    ///    Client's           Server            |           /  ||         |
    ///    Host Transport     Transport         |         //   ||         |
    ///    Address            Address           |       //     |+---------+
    /// 198.51.100.2:49721  192.0.2.15:3478     |+-+  //     Peer A
    ///            |            |               ||N| /       Host Transport
    ///            |   +-+      |               ||A|/        Address
    ///            |   | |      |               v|T|     203.0.113.2:49582
    ///            |   | |      |               /+-+
    /// +---------+|   | |      |+---------+   /              +---------+
    /// |         ||   |N|      ||         | //               |         |
    /// | TURN    |v   | |      v| TURN    |/                 |         |
    /// | Client  |----|A|-------| Server  |------------------|  Peer B |
    /// |         |    | |^      |         |^                ^|         |
    /// |         |    |T||      |         ||                ||         |
    /// +---------+    | ||      +---------+|                |+---------+
    ///                | ||                 |                |
    ///                | ||                 |                |
    ///                +-+|                 |                |
    ///                   |                 |                |
    ///                   |                 |                |
    ///          Client's                   |             Peer B
    ///          Server-Reflexive     Relayed             Transport
    ///          Transport Address    Transport Address   Address
    ///          192.0.2.1:7000       192.0.2.15:50000    192.0.2.210:49191
    ///
    ///                                Figure 1
    /// ```
    ///
    /// Figure 1 shows a typical deployment.  In this figure, the TURN client
    /// and the TURN server are separated by a NAT, with the client on the
    /// private side and the server on the public side of the NAT.  This NAT
    /// is assumed to be a "bad" NAT; for example, it might have a mapping
    /// property of "address-and-port-dependent mapping" (see [RFC4787]).
    ///
    /// The client talks to the server from a (IP address, port) combination
    /// called the client's "host transport address".  (The combination of an
    /// IP address and port is called a "transport address".)
    ///
    /// The client sends TURN messages from its host transport address to a
    /// transport address on the TURN server that is known as the "TURN
    /// server transport address".  The client learns the TURN server
    /// transport address through some unspecified means (e.g.,
    /// configuration), and this address is typically used by many clients
    /// simultaneously.
    ///
    /// Since the client is behind a NAT, the server sees packets from the
    /// client as coming from a transport address on the NAT itself.  This
    /// address is known as the client's "server-reflexive transport
    /// address"; packets sent by the server to the client's server-reflexive
    /// transport address will be forwarded by the NAT to the client's host
    /// transport address.
    ///
    /// The client uses TURN commands to create and manipulate an ALLOCATION
    /// on the server.  An allocation is a data structure on the server.
    /// This data structure contains, amongst other things, the relayed
    /// transport address for the allocation.  The relayed transport address
    /// is the transport address on the server that peers can use to have the
    /// server relay data to the client.  An allocation is uniquely
    /// identified by its relayed transport address.
    ///
    /// Once an allocation is created, the client can send application data
    /// to the server along with an indication of to which peer the data is
    /// to be sent, and the server will relay this data to the intended peer.
    /// The client sends the application data to the server inside a TURN
    /// message; at the server, the data is extracted from the TURN message
    /// and sent to the peer in a UDP datagram.  In the reverse direction, a
    /// peer can send application data in a UDP datagram to the relayed
    /// transport address for the allocation; the server will then
    /// encapsulate this data inside a TURN message and send it to the client
    /// along with an indication of which peer sent the data.  Since the TURN
    /// message always contains an indication of which peer the client is
    /// communicating with, the client can use a single allocation to
    /// communicate with multiple peers.
    ///
    /// When the peer is behind a NAT, the client must identify the peer
    /// using its server-reflexive transport address rather than its host
    /// transport address.  For example, to send application data to Peer A
    /// in the example above, the client must specify 192.0.2.150:32102 (Peer
    /// A's server-reflexive transport address) rather than 203.0.113.2:49582
    /// (Peer A's host transport address).
    ///
    /// Each allocation on the server belongs to a single client and has
    /// either one or two relayed transport addresses that are used only by
    /// that allocation.  Thus, when a packet arrives at a relayed transport
    /// address on the server, the server knows for which client the data is
    /// intended.
    ///
    /// The client may have multiple allocations on a server at the same
    /// time.
    public Result<Response, StunError> route(
        Span<uint8> bytes,
        SocketAddress address
    ) mut
    {
        this.address.address = address;

        if (decoder.decode(bytes) case .Ok(let payload))
        {
            switch(payload)
            {
                case .ChannelData(let channel):
                    return TOChannelData.process(
                        bytes,
                        Request(this.address, bytes, service, channel));

                case .Message(let message):
                    Method.StunMethod method = message.method();
                    Request req = Request(
                        this.address,
                        bytes,
                        service,
                        message
                    );
    
                    switch (method)
                    {
                    case .BINDING_REQUEST: return Binding.process(req);
                    case .ALLOCATE_REQUEST: return TOAllocate.process(req);
                    case .CREATE_PERMISSION_REQUEST: return CreatePermission.process(req);
                    case .CHANNEL_BIND_REQUEST: return ChannelBind.process(req);
                    case .REFRESH_REQUEST: return Refresh.process(req);
                    case .SEND_INDICATION: return Indication.process(req);
                    default: return .Err(.InvalidInput);
                    }
            }
        }

        return .Err(.InvalidInput);
    }
}
