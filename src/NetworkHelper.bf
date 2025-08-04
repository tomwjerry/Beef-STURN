namespace BeefSturn;
using System;
using Beef_Net;

static
{
    public static SocketAddress ParseSocketAddress(StringView value)
    {
        var addr = value.Split(':');
        StringView ip = addr.GetNext();
        uint16 port = UInt16.Parse(addr.GetNext());
        sa_family_t family = AF_INET;
        // IPv6
        if (addr.HasMore)
        {
            family = AF_INET6;
            ip = value.Substring(0, value.LastIndexOf(':'));
            port = UInt16.Parse(value.Substring(value.LastIndexOf(':') + 1));
        }

        SocketAddress sa = SocketAddress();
        Common.FillAddressInfo(ref sa, family, ip, port);
        return sa;
    }
}
