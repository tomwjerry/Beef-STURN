namespace BeefSturn.Turn.Operations;

using System;
using System.Collections;
using BeefSturn.Stun;
using Beef_Net;

class CreatePermission
{
    /// return create permission error response
    public static Result<Response, StunError> reject(Request req, HttpErrorKind err)
    {
        {
            MessageEncoder message = scope MessageEncoder();
            MessageEncoder.extend(.CREATE_PERMISSION_ERROR, req.message, req.bytes, message);
            message.appendAttr<ErrorCode>(ErrorCode(StunRespError.from(err)));
            message.appendAttr<Realm>(Realm(req.service.realm));
            if (message.flush(null) case .Err(let terr))
            {
                return .Err(terr);
            }
        }

        return Response()
        {
            method = ResponseMethod.Stun(.CREATE_PERMISSION_ERROR),
            bytes = req.bytes
        };
    }

    /// return create permission ok response
    public static Result<Response, StunError> resolve(Request req, uint8[16] integrity)
    {
        {
            MessageEncoder message = scope MessageEncoder();
            MessageEncoder.extend(.CREATE_PERMISSION_RESPONSE, req.message, req.bytes, message);
            message.appendAttr<Software>(Software(req.service.software));
            if (message.flush(null) case .Err(let terr))
            {
                return .Err(terr);
            }
        }

        return Response()
        {
            method = ResponseMethod.Stun(.CREATE_PERMISSION_RESPONSE),
            bytes = req.bytes
        };
    }

    /// process create permission request
    ///
    /// [rfc8489](https://tools.ietf.org/html/rfc8489)
    ///
    /// When the server receives the CreatePermission request, it processes
    /// as per [Section 5](https://tools.ietf.org/html/rfc8656#section-5)
    /// plus the specific rules mentioned here.
    ///
    /// The message is checked for validity.  The CreatePermission request
    /// MUST contain at least one XOR-PEER-ADDRESS attribute and MAY contain
    /// multiple such attributes.  If no such attribute exists, or if any of
    /// these attributes are invalid, then a 400 (Bad Request) error is
    /// returned.  If the request is valid, but the server is unable to
    /// satisfy the request due to some capacity limit or similar, then a 508
    /// (Insufficient Capacity) error is returned.
    ///
    /// If an XOR-PEER-ADDRESS attribute contains an address of an address
    /// family that is not the same as that of a relayed transport address
    /// for the allocation, the server MUST generate an error response with
    /// the 443 (Peer Address Family Mismatch) response code.
    ///
    /// The server MAY impose restrictions on the IP address allowed in the
    /// XOR-PEER-ADDRESS attribute; if a value is not allowed, the server
    /// rejects the request with a 403 (Forbidden) error.
    ///
    /// If the message is valid and the server is capable of carrying out the
    /// request, then the server installs or refreshes a permission for the
    /// IP address contained in each XOR-PEER-ADDRESS attribute as described
    /// in [Section 9](https://tools.ietf.org/html/rfc8656#section-9).  
    /// The port portion of each attribute is ignored and may be any arbitrary
    /// value.
    ///
    /// The server then responds with a CreatePermission success response.
    /// There are no mandatory attributes in the success response.
    ///
    /// > NOTE: A server need not do anything special to implement idempotency of
    /// > CreatePermission requests over UDP using the "stateless stack approach".
    /// > Retransmitted CreatePermission requests will simply refresh the
    /// > permissions.
    public static Result<Response, StunError> process(Request req)
    {
        (StringView, uint8[16]) unameNInte;
        if (!(req.auth() case .Ok(out unameNInte)))
        {
            return reject(req, HttpErrorKind.Unauthorized);
        }

        List<uint16> ports = scope List<uint16>(15);
        for (let it in req.message.get_all<XorPeerAddress>())
        {
            if (!req.verify_ip(it.addr))
            {
                return reject(req, HttpErrorKind.PeerAddressFamilyMismatch);
            }

            uint16 port = 0;
            if (it.addr.Family == AF_INET)
            {
                port = it.addr.u.IPv4.sin_port;
            }
            else
            {
                port = it.addr.u.IPv6.sin6_port;
            }

            ports.Add(port);
        }

        if (!req.service.sessions
            .create_permission(req.address, req.service.endpoint, ports))
        {
            return reject(req, HttpErrorKind.Forbidden);
        }

        req.service.observer.create_permission(req.address, unameNInte.0, ports);
        return resolve(req, unameNInte.1);
    }
}
