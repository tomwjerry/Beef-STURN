namespace BeefSturn;
using System;
using System.Collections;
using System.IO;
using Beef_Net;

enum Transport
{
    case TCP = 0;
    case UDP = 1;

    public static Result<Transport, StringView> FromStr(StringView value)
    {
        if (value.Equals("udp", true))
        {
            return .Ok(UDP);
        }
        else if (value.Equals("tcp", true))
        {
            return .Ok(TCP);
        }

        return .Err("unknown transport: {value}");
    }
}

struct CfgInterface
{
    public Transport transport;
    /// turn server listen address
    public (uint16, StringView) bind;
    /// external address
    ///
    /// specify the node external address and port.
    /// for the case of exposing the service to the outside,
    /// you need to manually specify the server external IP
    /// address and service listening port.
    public SocketAddress external;

    public this()
    {
        this = default;
    }
 
    public static Result<CfgInterface, StringView> FromStr(StringView s)
    {
        var tranportAddr = s.Split('@');
        StringView transportStr = tranportAddr.GetNext();
        Transport transport;
        if (!(Transport.FromStr(transportStr) case .Ok(out transport)))
        {
            return .Err("invalid interface transport: {s}");
        }
        var bindExternal = tranportAddr.GetNext().Get().Split('/');
        StringView bindStr = bindExternal.GetNext();
        StringView externalStr = bindExternal.GetNext();
        SocketAddress external = ParseSocketAddress(externalStr);

        uint16 bindPort = UInt8.Parse(bindStr.Substring(bindStr.LastIndexOf(':')));

        return .Ok(CfgInterface {
            external = external,
            bind = (bindPort, bindStr.Substring(0, bindStr.LastIndexOf(':'))),
            transport = transport
        });
    }
}

enum LogLevel
{
    case Error;
    case Warn;
    case Info;
    case Debug;
    case Trace;
    
    public static Result<LogLevel, String> FromStr(StringView value)
    {
        if (value.Equals("trace"))
        {
            return .Ok(Trace);
        }
        else if (value.Equals("debug"))
        {
            return .Ok(Debug);
        }
        else if (value.Equals("info"))
        {
            return .Ok(Info);
        }
        else if (value.Equals("warn"))
        {
            return .Ok(Warn);
        }
        else if (value.Equals("error"))
        {
            return .Ok(Error);
        }
        return .Err("unknown log level: {value}");
    }
}

class Config
{
    /// turn server realm
    ///
    /// specify the domain where the server is located.
    /// for a single node, this configuration is fixed,
    /// but each node can be configured as a different domain.
    /// this is a good idea to divide the nodes by namespace.
    public StringView realm;
    /// turn server listen interfaces
    ///
    /// The address and port to which the UDP Server is bound. Multiple
    /// addresses can be bound at the same time. The binding address supports
    /// ipv4 and ipv6.
    public List<CfgInterface> interfaces;

    public LogLevel log;

    /// static user password
    ///
    /// This option can be used to specify the
    /// static identity authentication information used by the turn server for
    /// verification. Note: this is a high-priority authentication method, turn
    /// The server will try to use static authentication first, and then use
    /// external control service authentication.
    public Dictionary<StringView, StringView> static_credentials;
    /// Static authentication key value (string) that applies only to the TURN
    /// REST API.
    ///
    /// If set, the turn server will not request external services via the HTTP
    /// Hooks API to obtain the key.
    public StringView static_auth_secret;

    public this()
    {
        realm = StringView("localhost");
        interfaces = new List<CfgInterface>();
        log = .Info;
        static_credentials = new Dictionary<StringView, StringView>();
    }

    public this(Config configcpy)
    {
        realm = StringView(configcpy.realm);
        interfaces = new List<CfgInterface>(configcpy.interfaces);
        log = configcpy.log;
        static_credentials = new Dictionary<StringView, StringView>(configcpy.static_credentials.GetEnumerator());
        static_auth_secret = StringView(configcpy.static_auth_secret);
    }

    public ~this()
    {
        delete interfaces;
        delete static_credentials;
    }

    public Span<SocketAddress> get_externals()
    {
        List<SocketAddress> externals = scope List<SocketAddress>();
        for (let it in interfaces)
        {
            externals.Add(it.external);
        }
        return externals;
    }
}
