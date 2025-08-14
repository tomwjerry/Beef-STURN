namespace BeefSturn.Turn.Operations;

using System;
using System.Collections;
using BeefSturn.Stun;
using Beef_Net;

class Indication
{
    /// @brief process send indication request
    ///
    /// When the server receives a Send indication, it processes as per
    /// [Section 5](https://tools.ietf.org/html/rfc8656#section-5) plus
    /// the specific rules mentioned here.
    ///
    /// The message is first checked for validity.  The Send indication MUST
    /// contain both an XOR-PEER-ADDRESS attribute and a DATA attribute.  If
    /// one of these attributes is missing or invalid, then the message is
    /// discarded.  Note that the DATA attribute is allowed to contain zero
    /// bytes of data.
    ///
    /// The Send indication may also contain the DONT-FRAGMENT attribute.  If
    /// the server is unable to set the DF bit on outgoing UDP datagrams when
    /// this attribute is present, then the server acts as if the DONT-
    /// FRAGMENT attribute is an unknown comprehension-required attribute
    /// (and thus the Send indication is discarded).
    ///
    /// The server also checks that there is a permission installed for the
    /// IP address contained in the XOR-PEER-ADDRESS attribute.  If no such
    /// permission exists, the message is discarded.  Note that a Send
    /// indication never causes the server to refresh the permission.
    ///
    /// The server MAY impose restrictions on the IP address and port values
    /// allowed in the XOR-PEER-ADDRESS attribute; if a value is not allowed,
    /// the server silently discards the Send indication.
    ///
    /// If everything is OK, then the server forms a UDP datagram as follows:
    ///
    /// * the source transport address is the relayed transport address of the
    ///   allocation, where the allocation is determined by the 5-tuple on which the
    ///   Send indication arrived;
    ///
    /// * the destination transport address is taken from the XOR-PEER-ADDRESS
    ///   attribute;
    ///
    /// * the data following the UDP header is the contents of the value field of
    ///   the DATA attribute.
    ///
    /// The handling of the DONT-FRAGMENT attribute (if present), is
    /// described in Sections [14](https://tools.ietf.org/html/rfc8656#section-14)
    /// and [15](https://tools.ietf.org/html/rfc8656#section-15).
    ///
    /// The resulting UDP datagram is then sent to the peer.
    public static Result<Response, StunError> process(Request req)
    {
        XorPeerAddress peer = req.message.getAttr<XorPeerAddress>();
        Data data = req.message.getAttr<Data>();
        uint16 port = 0;
        if (peer.addr.Family == AF_INET)
        {
            port = peer.addr.u.IPv4.sin_port;
        }
        else
        {
            port = peer.addr.u.IPv6.sin6_port;
        }
    
        Endpoint? relay = req.service.sessions.get_relay_address(req.address, port);
        uint16 local_port = req.service.sessions
            .get_session(req.address).allocate.port;
    
        {
            MessageEncoder message = scope MessageEncoder();
            MessageEncoder.extend(.DATA_INDICATION, req.message, req.bytes, message);
            SocketAddress sockAddr = req.service.sainterface;
            if (sockAddr.Family == AF_INET)
            {
                sockAddr.u.IPv4.sin_port = local_port;
            }
            else
            {
                sockAddr.u.IPv6.sin6_port = local_port;
            }
            message.appendAttr<XorPeerAddress>(XorPeerAddress(sockAddr));
            message.appendAttr<Data>(data);

            if (message.flush(null) case .Err(let terr))
            {
                req.Dispose();
                return .Err(terr);
            }
        }

        if (relay.HasValue && relay.Value.endpoint != req.service.endpoint)
        {
            relay = null;
        }

        Span<uint8> bytes = Span<uint8>(req.bytes.Ptr, req.bytes.Count);
        req.Dispose();
    
        return Response()
        {
            method = ResponseMethod.Stun(.DATA_INDICATION),
            endpoint = relay.HasValue ? relay.Value.endpoint : null,
            relay = relay.HasValue ? relay.Value.address : null,
            bytes = bytes
        };
    }
}
