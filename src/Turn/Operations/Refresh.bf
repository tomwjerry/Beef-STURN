namespace BeefSturn.Turn.Operations;

using System;
using System.Collections;
using BeefSturn.Stun;
using Beef_Net;

class Refresh
{
    /// return refresh error response
    public static Result<Response, StunError> reject(Request req, HttpErrorKind err)
    {
        {
            MessageEncoder message = scope MessageEncoder();
            MessageEncoder.extend(.REFRESH_ERROR, req.message, req.bytes, message);
            message.appendAttr<ErrorCode>(ErrorCode(StunRespError.from(err)));
            if (message.flush(null) case .Err(let terr))
            {
                return .Err(terr);
            }
        }

        Span<uint8> bytes = Span<uint8>(req.bytes.Ptr, req.bytes.Count);

        return Response()
        {
            method = ResponseMethod.Stun(.REFRESH_ERROR),
            bytes = bytes
        };
    }

    /// return refresh ok response
    public static Result<Response, StunError> resolve(Request req, uint32 lifetime, uint8[16] integrity)
    {
        {
            MessageEncoder message = scope MessageEncoder();
            MessageEncoder.extend(.REFRESH_RESPONSE, req.message, req.bytes, message);
            message.appendAttr<Lifetime>(Lifetime(lifetime));
            if (message.flush(Digest(integrity)) case .Err(let terr))
            {
                return .Err(terr);
            }
        }

        Span<uint8> bytes = Span<uint8>(req.bytes.Ptr, req.bytes.Count);

        return Response()
        {
            method = ResponseMethod.Stun(.REFRESH_RESPONSE),
            bytes = bytes
        };
    }

    /// @brief process refresh request
    ///
    /// If the server receives a Refresh Request with a REQUESTED-ADDRESS-
    /// FAMILY attribute and the attribute value does not match the address
    /// family of the allocation, the server MUST reply with a 443 (Peer
    /// Address Family Mismatch) Refresh error response.
    ///
    /// The server computes a value called the "desired lifetime" as follows:
    /// if the request contains a LIFETIME attribute and the attribute value
    /// is zero, then the "desired lifetime" is zero.  Otherwise, if the
    /// request contains a LIFETIME attribute, then the server computes the
    /// minimum of the client's requested lifetime and the server's maximum
    /// allowed lifetime.  If this computed value is greater than the default
    /// lifetime, then the "desired lifetime" is the computed value.
    /// Otherwise, the "desired lifetime" is the default lifetime.
    ///
    /// Subsequent processing depends on the "desired lifetime" value:
    ///
    /// * If the "desired lifetime" is zero, then the request succeeds and the
    ///   allocation is deleted.
    ///
    /// * If the "desired lifetime" is non-zero, then the request succeeds and the
    ///   allocation's time-to-expiry is set to the "desired lifetime".
    ///
    /// If the request succeeds, then the server sends a success response
    /// containing:
    ///
    /// * A LIFETIME attribute containing the current value of the time-to-expiry
    ///   timer.
    ///
    /// NOTE: A server need not do anything special to implement
    /// idempotency of Refresh requests over UDP using the "stateless
    /// stack approach".  Retransmitted Refresh requests with a non-
    /// zero "desired lifetime" will simply refresh the allocation.  A
    /// retransmitted Refresh request with a zero "desired lifetime"
    /// will cause a 437 (Allocation Mismatch) response if the
    /// allocation has already been deleted, but the client will treat
    /// this as equivalent to a success response (see below).
    public static Result<Response, StunError> process(Request req)
    {
        (StringView, uint8[16]) unameNInte;
        if (!(req.auth() case .Ok(out unameNInte)))
        {
            return reject(req, HttpErrorKind.Unauthorized);
        }

        uint32 lifetime = 600;
        if (req.message.getAttr<Lifetime>() case .Ok(let lifetimeObj))
        {
            lifetime = lifetimeObj.lifetime;
        }

        if (!req.service.sessions.refresh(req.address, lifetime))
        {
            return reject(req, HttpErrorKind.AllocationMismatch);
        }

        req.service.observer.refresh(req.address, unameNInte.0, lifetime);
        return resolve(req, lifetime, unameNInte.1);
    }
}
