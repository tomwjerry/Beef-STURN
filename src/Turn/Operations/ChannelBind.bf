namespace BeefSturn.Turn.Operations;

using System;
using BeefSturn.Stun;
using Beef_Net;

/// return channel binding error response
class ChannelBind
{
    public static Result<Response, StunError> reject(Request req, HttpErrorKind err)
    {
        {
            MessageEncoder message = scope MessageEncoder();
            MessageEncoder.extend(.CHANNEL_BIND_ERROR, req.message, req.bytes, message);
            message.appendAttr<ErrorCode>(ErrorCode(StunRespError.from(err)));
            message.appendAttr<Realm>(Realm(req.service.realm));
            if (message.flush(null) case .Err(let terr))
            {
                req.Dispose();
                return .Err(terr);
            }
        }

        Span<uint8> bytes = Span<uint8>(req.bytes.Ptr, req.bytes.Count);
        req.Dispose();

        return Response()
        {
            method = ResponseMethod.Stun(.CHANNEL_BIND_ERROR),
            bytes = bytes,
            endpoint = null,
            relay = null
        };
    }

    /// return channel binding ok response
    public static Result<Response, StunError> resolve(Request req, uint8[16] integrity)
    {
        {
            MessageEncoder message = scope MessageEncoder();
            MessageEncoder.extend(.CHANNEL_BIND_RESPONSE, req.message, req.bytes, message);
            if (message.flush(Digest(integrity)) case .Err(let err))
            {
                req.Dispose();
                return .Err(err);
            }
        }

        Span<uint8> bytes = Span<uint8>(req.bytes.Ptr, req.bytes.Count);
        req.Dispose();

        return Response()
        {
            method = ResponseMethod.Stun(.CHANNEL_BIND_RESPONSE),
            bytes = bytes,
            endpoint = null,
            relay = null
        };
    }

    /// @brief process channel binding request
    ///
    /// The server MAY impose restrictions on the IP address and port values
    /// allowed in the XOR-PEER-ADDRESS attribute; if a value is not allowed,
    /// the server rejects the request with a 403 (Forbidden) error.
    ///
    /// If the request is valid, but the server is unable to fulfill the
    /// request due to some capacity limit or similar, the server replies
    /// with a 508 (Insufficient Capacity) error.
    ///
    /// Otherwise, the server replies with a ChannelBind success response.
    /// There are no required attributes in a successful ChannelBind
    /// response.
    ///
    /// If the server can satisfy the request, then the server creates or
    /// refreshes the channel binding using the channel number in the
    /// CHANNEL-NUMBER attribute and the transport address in the XOR-PEER-
    /// ADDRESS attribute.  The server also installs or refreshes a
    /// permission for the IP address in the XOR-PEER-ADDRESS attribute as
    /// described in Section 9.
    ///
    /// NOTE: A server need not do anything special to implement
    /// idempotency of ChannelBind requests over UDP using the
    /// "stateless stack approach".  Retransmitted ChannelBind requests
    /// will simply refresh the channel binding and the corresponding
    /// permission.  Furthermore, the client must wait 5 minutes before
    /// binding a previously bound channel number or peer address to a
    /// different channel, eliminating the possibility that the
    /// transaction would initially fail but succeed on a
    /// retransmission.
    public static Result<Response, StunError> process(Request req)
    {
        XorPeerAddress peer;
        if (!(req.message.getAttr<XorPeerAddress>() case .Ok(out peer)))
        {
            return reject(req, HttpErrorKind.BadRequest);
        }

        if (!req.verify_ip(peer.addr))
        {
            return reject(req, HttpErrorKind.PeerAddressFamilyMismatch);
        }

        ChannelNumber number;
        
        if (!(req.message.getAttr<ChannelNumber>() case .Ok(out number)))
        {
            return reject(req, HttpErrorKind.BadRequest);
        }

        if (number.number < 0x4000 || number.number > 0x7FFF)
        {
            return reject(req, HttpErrorKind.BadRequest);
        }

        (StringView, uint8[16]) unameNInte;
        if (!(req.auth() case .Ok(out unameNInte)))
        {
            return reject(req, HttpErrorKind.Unauthorized);
        }

        uint16 port = 0;
        if (peer.addr.Family == AF_INET)
        {
            port = peer.addr.u.IPv4.sin_port;
        }
        else
        {
            port = peer.addr.u.IPv6.sin6_port;
        }

        if (!req.service.sessions
            .bind_channel(req.address, req.service.endpoint, port, number.number))
        {
            return reject(req, HttpErrorKind.Forbidden);
        }

        req.service.observer.channel_bind(req.address, unameNInte.0, number.number);
        return resolve(req, unameNInte.1);
    }
}
