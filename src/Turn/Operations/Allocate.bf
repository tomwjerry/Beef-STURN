namespace BeefSturn.Turn.Operations;

using System;
using BeefSturn.Stun;
using Beef_Net;

class TOAllocate
{
    /// return allocate error response
    public static Result<Response, StunError> reject(Request req, HttpErrorKind err)
    {
        {
            MessageEncoder message = scope MessageEncoder();
            MessageEncoder.extend(.ALLOCATE_ERROR, req.message, req.bytes, message);
            message.appendAttr<ErrorCode>(ErrorCode(StunRespError.from(err)));
            let nonceInfo = req.service.sessions.get_nonce(req.address);
            message.appendAttr<Nonce>(Nonce(nonceInfo.0));
            message.appendAttr<Realm>(Realm(req.service.realm));
            if (message.flush(null) case .Err(let terr))
            {
                req.Dispose();
                return .Err(terr);
            }
        }

        Span<uint8> bytes = Span<uint8>(req.bytes.Ptr, req.bytes.Count);
        req.Dispose();

        return .Ok(Response()
        {
            method = ResponseMethod.Stun(.ALLOCATE_ERROR),
            bytes = bytes,
            endpoint = null,
            relay = null
        });
    }

    /// @breif return allocate ok response
    ///
    /// NOTE: The use of randomized port assignments to avoid certain
    /// types of attacks is described in [RFC6056].  It is RECOMMENDED
    /// that a TURN server implement a randomized port assignment
    /// algorithm from [RFC6056].  This is especially applicable to
    /// servers that choose to pre-allocate a number of ports from the
    /// underlying OS and then later assign them to allocations; for
    /// example, a server may choose this technique to implement the
    /// EVEN-PORT attribute.
    public static Result<Response, StunError> resolve(
        Request req,
        uint8[16] integrity,
        uint16 port
    )
    {
        {
            MessageEncoder message = scope MessageEncoder();
            MessageEncoder.extend(.ALLOCATE_RESPONSE, req.message, req.bytes, message);
            SocketAddress sockAddr = req.service.sainterface;
            if (sockAddr.Family == AF_INET)
            {
                sockAddr.u.IPv4.sin_port = port;
            }
            else
            {
                sockAddr.u.IPv6.sin6_port = port;
            }
            message.appendAttr<XorRelayedAddress>(XorRelayedAddress(sockAddr));
            message.appendAttr<XorMappedAddress>(XorMappedAddress(req.address.address));
            message.appendAttr<Lifetime>(Lifetime(600));
            message.appendAttr<Software>(Software(req.service.software));
            if (message.flush(Digest(integrity)) case .Err(let terr))
            {
                req.Dispose();
                return .Err(terr);
            }
        }

        Span<uint8> bytes = Span<uint8>(req.bytes.Ptr, req.bytes.Count);
        req.Dispose();

        return Response()
        {
            method = ResponseMethod.Stun(.ALLOCATE_RESPONSE),
            bytes = bytes,
            endpoint = null,
            relay = null
        };
    }

    /// @brief process allocate request
    ///
    /// [rfc8489](https://tools.ietf.org/html/rfc8489)
    ///
    /// In all cases, the server SHOULD only allocate ports from the range
    /// 49152 - 65535 (the Dynamic and/or Private Port range [PORT-NUMBERS]),
    /// unless the TURN server application knows, through some means not
    /// specified here, that other applications running on the same host as
    /// the TURN server application will not be impacted by allocating ports
    /// outside this range.  This condition can often be satisfied by running
    /// the TURN server application on a dedicated machine and/or by
    /// arranging that any other applications on the machine allocate ports
    /// before the TURN server application starts.  In any case, the TURN
    /// server SHOULD NOT allocate ports in the range 0 - 1023 (the Well-
    /// Known Port range) to discourage clients from using TURN to run
    /// standard services.
    public static Result<Response, StunError> process(Request req)
    {
        if (req.message.getAttr<RequestedTransport>() case .Err)
        {
            return reject(req, HttpErrorKind.ServerError);
        }

        (StringView, uint8[16]) unameNInte;

        if (!(req.auth() case .Ok(out unameNInte)))
        {
            return reject(req, HttpErrorKind.Unauthorized);
        }

        uint16 port = req.service.sessions.allocate(req.address);

        if (port == 0)
        {
            return reject(req, HttpErrorKind.AllocationQuotaReached);
        }

        req.service.observer.allocated(req.address, unameNInte.0, port);
        return resolve(req, unameNInte.1, port);
    }
}
