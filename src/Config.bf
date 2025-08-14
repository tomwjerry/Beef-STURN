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

struct TurnCfg : IDisposable
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

    public this()
    {
        this = default;
        realm = "localhost";
        interfaces = new List<CfgInterface>();
    }

    public void Dispose()
    {
        delete interfaces;
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

struct Api
{
    /// api bind
    ///
    /// This option specifies the http server binding address used to control
    /// the turn server.
    ///
    /// Warn: This http server does not contain any means of authentication,
    /// and sensitive information and dangerous operations can be obtained
    /// through this service, please do not expose it directly to an unsafe
    /// environment.
    public SocketAddress bind;

    public this
    {
        this = default;
        bind = SocketAddress();
        bind.Family = AF_INET;
        bind.u = SocketAddress.USockAddr();
        bind.u.IPv4.sin_family = AF_INET;
        bind.u.IPv4.sin_port = 300;
        bind.u.IPv4.sin_addr = in_addr();
        bind.u.IPv4.sin_addr.s_bytes = uint8[4](127, 0, 0, 1);
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

struct Log
{
    /// log level
    ///
    /// An enum representing the available verbosity levels of the logger.
    public LogLevel level;

    public static void Info(StringView msg, params Object[] msgParams)
    {
        Console.WriteLine(msg, msgParams);
    }

    public static void Error(StringView msg, params Object[] msgParams)
    {
        Console.WriteLine(msg, msgParams);
    }
}

struct Auth : IDisposable
{
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
        this = default;
        static_credentials = new Dictionary<StringView, StringView>();
        static_auth_secret = "";
    }

    public void Dispose()
    {
        delete static_credentials;
    }
}

struct Config
{
    public TurnCfg turn;
    public Api api;
    public Log log;
    public Auth auth;

    /// Load configure from config file and command line parameters.
    ///
    /// Load command line parameters, if the configuration file path is
    /// specified, the configuration is read from the configuration file,
    /// otherwise the default configuration is used.
    public static Result<Config> load(String[] cfgarg)
    {
        Config conf = Config();
        conf.turn = TurnCfg();
        conf.api = Api();
        conf.log = Log();
        conf.auth = Auth();

        // If you want to load config from file, perhaps best way is to make a function that loads the file
        // then set the config variables

        // Command line arguments have a high priority and override configuration file
        // options; here they are used to replace the configuration parsed out of the
        // configuration file.
        for (int i = 0; i < cfgarg.Count; i++)
        {
            if (cfgarg[i] == "--auth-static-credentials")
            {
                i++;
                if (Cli.parse_credential(cfgarg[i]) case .Ok(let cred))
                {
                    conf.auth.static_credentials.Add(cred);
                }
            }
            else if (cfgarg[i] == "--auth-static-auth-secret")
            {
                i++;
                conf.auth.static_auth_secret = cfgarg[i];
            }
            else if (cfgarg[i] == "--log-level")
            {
                i++;
                conf.log.level = LogLevel.FromStr(cfgarg[i]);
            }
            else if (cfgarg[i] == "--api-bind")
            {
                i++;
                conf.api.bind = ParseSocketAddress(cfgarg[i]);
            }
            else if (cfgarg[i] == "--turn-realm")
            {
                i++;
                conf.turn.realm = cfgarg[i];
            }
            else if (cfgarg[i] == "--turn-interfaces")
            {
                i++;
                conf.turn.interfaces.Add(CfgInterface.FromStr(cfgarg[i]));
            }
        }

        // Filters out transport protocols that are not enabled.
        // TODO?

        return .Ok(conf);
    }
}

struct Cli : IDisposable
{
    /// Specify the configuration file path
    ///
    /// Example: --config /etc/turn-rs/config.toml
    public StringView config;
    /// Static user password
    ///
    /// Example: --auth-static-credentials test=test
    public List<(StringView, StringView)> auth_static_credentials;
    /// Static authentication key value (string) that applies only to the TURN
    /// REST API
    public StringView auth_static_auth_secret;
    /// An enum representing the available verbosity levels of the logger
    public LogLevel log_level;
    /// This option specifies the http server binding address used to control
    /// the turn server
    public SocketAddress? api_bind;
    /// TURN server realm
    public StringView turn_realm;
    /// TURN server listen interfaces
    ///
    /// Example: --turn-interfaces udp@127.0.0.1:3478/127.0.0.1:3478
    public List<CfgInterface> turn_interfaces;

    public this()
    {
        this = default;
        auth_static_credentials = new List<(StringView, StringView)>();
        turn_interfaces = new List<CfgInterface>();
    }

    public void Dispose()
    {
        delete auth_static_credentials;
        delete turn_interfaces;
    }

    // [username]:[password]
    public static Result<(StringView, StringView), StringView> parse_credential(StringView s)
    {
        var unamePwd = s.Split('=');
        return .Ok((unamePwd.GetNext(), unamePwd.GetNext()));
    }
}
