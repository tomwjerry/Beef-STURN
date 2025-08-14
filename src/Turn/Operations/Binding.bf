namespace BeefSturn.Turn.Operations;

using System;
using BeefSturn.Stun;

/// @brief process binding request
///
/// [rfc8489](https://tools.ietf.org/html/rfc8489)
///
/// In the Binding request/response transaction, a Binding request is
/// sent from a STUN client to a STUN server.  When the Binding request
/// arrives at the STUN server, it may have passed through one or more
/// NATs between the STUN client and the STUN server (in Figure 1, there
/// are two such NATs).  As the Binding request message passes through a
/// NAT, the NAT will modify the source transport address (that is, the
/// source IP address and the source port) of the packet.  As a result,
/// the source transport address of the request received by the server
/// will be the public IP address and port created by the NAT closest to
/// the server.  This is called a "reflexive transport address".  The
/// STUN server copies that source transport address into an XOR-MAPPED-
/// ADDRESS attribute in the STUN Binding response and sends the Binding
/// response back to the STUN client.  As this packet passes back through
/// a NAT, the NAT will modify the destination transport address in the
/// IP header, but the transport address in the XOR-MAPPED-ADDRESS
/// attribute within the body of the STUN response will remain untouched.
/// In this way, the client can learn its reflexive transport address
/// allocated by the outermost NAT with respect to the STUN server.
class Binding
{
    public static Result<Response, StunError> process(Request req)
    {
        MessageEncoder message = scope MessageEncoder();
        MessageEncoder.extend(.BINDING_RESPONSE, req.message, req.bytes, message);
        message.appendAttr<XorMappedAddress>(XorMappedAddress(req.address.address));
        message.appendAttr<MappedAddress>(MappedAddress(req.address.address));
        message.appendAttr<ResponseOrigin>(ResponseOrigin(req.service.sainterface));
        message.appendAttr<Software>(Software(req.service.software));
        if (message.flush(null) case .Err(let err))
        {
            req.Dispose();
            return .Err(err);
        }

        Span<uint8> bytes = Span<uint8>(req.bytes.Ptr, req.bytes.Count);
        req.Dispose();
    
        return Response()
        {
            method = ResponseMethod.Stun(.BINDING_RESPONSE),
            bytes = bytes,
            endpoint = null,
            relay = null
        };
    }
}
