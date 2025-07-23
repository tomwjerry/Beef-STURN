namespace BeefSturn.Stun;

using System;
using System.Collections;
using System.Diagnostics;

//! ## Session Traversal Utilities for NAT (STUN)
//!
//! [RFC8445]: https://tools.ietf.org/html/rfc8445
//! [RFC5626]: https://tools.ietf.org/html/rfc5626
//! [Section 13]: https://tools.ietf.org/html/rfc8489#section-13
//!
//! ### STUN Message Structure
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transaction ID (96 bits)                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! ### STUN Attributes
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Type                  |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Value (variable)                ....
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! STUN is intended to be used in the context of one or more NAT
//! traversal solutions.  These solutions are known as "STUN Usages".
//! Each usage describes how STUN is utilized to achieve the NAT
//! traversal solution.  Typically, a usage indicates when STUN messages
//! get sent, which optional attributes to include, what server is used,
//! and what authentication mechanism is to be used.  Interactive
//! Connectivity Establishment (ICE) [RFC8445] is one usage of STUN.
//! SIP Outbound [RFC5626] is another usage of STUN.  In some cases,
//! a usage will require extensions to STUN. A STUN extension can be
//! in the form of new methods, attributes, or error response codes.
//! More information on STUN Usages can be found in [Section 13].

enum StunError
{
    case InvalidInput;
    case SummaryFailed;
    case NotFoundIntegrity;
    case IntegrityFailed;
    case NotFoundCookie;
    case UnknownStunMethod;
    case FatalError;
    case Utf8Error(StringView utf8Error);
    case TryFromSliceError(Span<uint8> tryFromSliceError);
}

class Method
{
    public static readonly StunMethod BINDING_REQUEST = StunMethod.Binding(StunMethodKind.Request);
    public static readonly StunMethod BINDING_RESPONSE = StunMethod.Binding(StunMethodKind.Response);
    public static readonly StunMethod BINDING_ERROR = StunMethod.Binding(StunMethodKind.Error);
    public static readonly StunMethod ALLOCATE_REQUEST = StunMethod.Allocate(StunMethodKind.Request);
    public static readonly StunMethod ALLOCATE_RESPONSE = StunMethod.Allocate(StunMethodKind.Response);
    public static readonly StunMethod ALLOCATE_ERROR = StunMethod.Allocate(StunMethodKind.Error);
    public static readonly StunMethod CREATE_PERMISSION_REQUEST = StunMethod.CreatePermission(StunMethodKind.Request);
    public static readonly StunMethod CREATE_PERMISSION_RESPONSE = StunMethod.CreatePermission(StunMethodKind.Response);
    public static readonly StunMethod CREATE_PERMISSION_ERROR = StunMethod.CreatePermission(StunMethodKind.Error);
    public static readonly StunMethod CHANNEL_BIND_REQUEST = StunMethod.ChannelBind(StunMethodKind.Request);
    public static readonly StunMethod CHANNEL_BIND_RESPONSE = StunMethod.ChannelBind(StunMethodKind.Response);
    public static readonly StunMethod CHANNEL_BIND_ERROR = StunMethod.ChannelBind(StunMethodKind.Error);
    public static readonly StunMethod REFRESH_REQUEST = StunMethod.Refresh(StunMethodKind.Request);
    public static readonly StunMethod REFRESH_RESPONSE = StunMethod.Refresh(StunMethodKind.Response);
    public static readonly StunMethod REFRESH_ERROR = StunMethod.Refresh(StunMethodKind.Error);
    public static readonly StunMethod SEND_INDICATION = StunMethod.SendIndication;
    public static readonly StunMethod DATA_INDICATION = StunMethod.DataIndication;

    /// STUN StunMethods Registry
    ///
    /// [RFC5389]: https://datatracker.ietf.org/doc/html/rfc5389
    /// [RFC8489]: https://datatracker.ietf.org/doc/html/rfc8489
    /// [RFC8126]: https://datatracker.ietf.org/doc/html/rfc8126
    /// [Section 5]: https://datatracker.ietf.org/doc/html/rfc8489#section-5
    ///
    /// A STUN method is a hex number in the range 0x000-0x0FF.  The encoding
    /// of a STUN method into a STUN message is described in [Section 5].
    ///
    /// STUN methods in the range 0x000-0x07F are assigned by IETF Review
    /// [RFC8126].  STUN methods in the range 0x080-0x0FF are assigned by
    /// Expert Review [RFC8126].  The responsibility of the expert is to
    /// verify that the selected codepoint(s) is not in use and that the
    /// request is not for an abnormally large number of codepoints.
    /// Technical review of the extension itself is outside the scope of the
    /// designated expert responsibility.
    ///
    /// IANA has updated the name for method 0x002 as described below as well
    /// as updated the reference from [RFC5389] to [RFC8489] for the following
    /// STUN methods:
    ///
    /// 0x000: Reserved
    /// 0x001: Binding
    /// 0x002: Reserved; was SharedSecret prior to [RFC5389]
    /// 0x003: Allocate
    /// 0x004: Refresh
    /// 0x006: Send
    /// 0x007: Data
    /// 0x008: CreatePermission
    /// 0x009: ChannelBind
    public enum StunMethodKind
    {
        Request,
        Response,
        Error
    }

    public enum StunMethod
    {
        case Binding(StunMethodKind);
        case Allocate(StunMethodKind);
        case CreatePermission(StunMethodKind);
        case ChannelBind(StunMethodKind);
        case Refresh(StunMethodKind);
        case SendIndication;
        case DataIndication;

        public bool is_error()
        {
            switch(this)
            {
            case Binding(let kindval): return kindval == StunMethodKind.Error;
            case Refresh(let kindval): return kindval == StunMethodKind.Error;
            case Allocate(let kindval): return kindval == StunMethodKind.Error;
            case CreatePermission(let kindval): return kindval == StunMethodKind.Error;
            case ChannelBind(let kindval): return kindval == StunMethodKind.Error;
            default: return false;
            }
        }

        public Result<StunMethod> TryFrom(uint16 fromval)
        {
            switch (fromval)
            {
            case 0x0001: return .Ok(Binding(StunMethodKind.Request));
            case 0x0101: return .Ok(Binding(StunMethodKind.Response));
            case 0x0111: return .Ok(Binding(StunMethodKind.Error));
            case 0x0003: return .Ok(Allocate(StunMethodKind.Request));
            case 0x0103: return .Ok(Allocate(StunMethodKind.Response));
            case 0x0113: return .Ok(Allocate(StunMethodKind.Error));
            case 0x0008: return .Ok(CreatePermission(StunMethodKind.Request));
            case 0x0108: return .Ok(CreatePermission(StunMethodKind.Response));
            case 0x0118: return .Ok(CreatePermission(StunMethodKind.Error));
            case 0x0009: return .Ok(ChannelBind(StunMethodKind.Request));
            case 0x0109: return .Ok(ChannelBind(StunMethodKind.Response));
            case 0x0119: return .Ok(ChannelBind(StunMethodKind.Error));
            case 0x0004: return .Ok(Refresh(StunMethodKind.Request));
            case 0x0104: return .Ok(Refresh(StunMethodKind.Response));
            case 0x0114: return .Ok(Refresh(StunMethodKind.Error));
            case 0x0016: return .Ok(SendIndication);
            case 0x0017: return .Ok(DataIndication);
            default: return .Err;
            }
        }

        public uint16 Into()
        {
            switch(this)
            {
            case .Binding(let kindval):
                if (kindval == .Request)
                {
                    return 0x0001;
                }
                else if (kindval == .Response)
                {
                    return 0x0101;
                }
                return 0x0111;
            case .Allocate(let kindval):
                if (kindval == .Request)
                {
                    return 0x0003;
                }
                else if (kindval == .Response)
                {
                    return 0x0103;
                }
                return 0x0113;
            case .CreatePermission(let kindval):
                if (kindval == .Request)
                {
                    return 0x0008;
                }
                else if (kindval == .Response)
                {
                    return 0x0108;
                }
                return 0x0118;
            case .ChannelBind(let kindval):
                if (kindval == .Request)
                {
                    return 0x0009;
                }
                else if (kindval == .Response)
                {
                    return 0x0109;
                }
                return 0x0119;
            case .Refresh(let kindval):
                if (kindval == .Request)
                {
                    return 0x0004;
                }
                else if (kindval == .Response)
                {
                    return 0x0104;
                }
                return 0x0114;
            case .SendIndication: return 0x0016;
            case .DataIndication: return 0x0017;
            default: return 0;
            }
        }
    }
}

enum Payload
{
    case Message(MessageRef msgref);
    case ChannelData(ChannelData channelData);
}

/// A cache of the list of attributes, this is for internal use only.
struct Attributes : IDisposable
{
    public List<(AttrKind, Span<uint64>)> attrList;

    public this()
    {
        attrList = new List<(AttrKind, Span<uint64>)>(20);
    }

    public void Dispose()
    {
        delete attrList;
    }

    /// Adds an attribute to the list.
    public void aAppend(AttrKind kind, Span<uint64> range)
    {
        attrList.Add((kind, range));
    }

    /// Gets an attribute from the list.
    ///
    /// Note: This function will only look for the first matching property in
    /// the list and return it.
    public Span<uint64> get(AttrKind kind)
    {
        int idx = attrList.FindIndex(scope(cmp) => cmp[0] == kind);
        if (idx > -1)
        {
            return attrList[idx][1];
        }

        return Span<uint64>();
    }

    /// Gets all the values of an attribute from a list.
    ///
    /// Normally a stun message can have multiple attributes with the same name,
    /// and this function will all the values of the current attribute.
    public Span<Span<uint64>>.Enumerator get_all(AttrKind kind)
    {
        List<Span<uint64>> filteredAttrs = scope List<Span<uint64>>();
        for (let li in attrList)
        {
            if (li[0] == kind)
            {
                filteredAttrs.Add(li[1]);
            }
        }

        return filteredAttrs.GetRange(0).GetEnumerator();
    }

    public void clear()
    {
        attrList.Clear();
    }
}

struct Decoder
{
    public Attributes attrs;

    public Result<Payload, StunError> decode(Span<uint8> bytes)
    {
        Debug.Assert(bytes.Length >= 4);

        let flag = bytes[0] >> 6;
        if (flag > 3)
        {
            return .Err(StunError.InvalidInput);
        }

        if (flag == 0)
        {
            attrs.clear();

            MessageRef msg;
            if (msg = MessageDecoder.decode(bytes, ref attrs))
            {
                return .Ok(Payload.Message());
            }
        }
        else
        {
            ChannelData chanData;
            if (chanData = ChannelData.try_from(bytes))
            {
                return .Ok(Payload.ChannelData(chanData));
            }
        }

        return .Err(.InvalidInput);
    }

    public Result<uint64, StunError> message_size(Span<uint8> bytes, bool is_tcp)
    {
        let flag = bytes[0] >> 6;
        if (flag > 3)
        {
            return .Err(StunError.InvalidInput);
        }

        if (flag == 0)
        {
            uint64? res = MessageDecoder.message_size(bytes);
            if (res != null)
            {
                return .Ok(res.Value);
            }
        }
        else
        {
            uint64? res = ChannelData.message_size(bytes, is_tcp);
            if (res != null)
            {
                return .Ok(res.Value);
            }
        }

        return .Err(StunError.InvalidInput);
    }
}
