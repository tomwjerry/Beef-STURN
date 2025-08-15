namespace BeefSturn;

using System;
using System.Collections;
using BeefSturn.Turn;
using Beef_Net;

class BeefSturn
{
    private List<Server> runners;

    /// start turn server.
    ///
    /// create a specified number of threads,
    /// each thread processes udp data separately.
    public Result<void> StartServer(Config config, Statistics statistics, Service lservice)
    {
        Beef_Net_Init();
        runners = new List<Server>();

        for (let intobj in config.interfaces)
        {
            ServerStartOptions options = scope ServerStartOptions()
            {
                statistics = new Statistics(statistics),
                service = new Service(lservice),
                router = new Router(),
                external = intobj.external,
                bind = intobj.bind
            };

            if (intobj.transport case .UDP)
            {
                SturnUDP sudp = new SturnUDP();
                sudp.start(options);
                runners.Add(sudp);
            }
            else if (intobj.transport case .TCP)
            {
                SturnTCP stcp = new SturnTCP();
                stcp.start(options);
                runners.Add(stcp);
            }
        }

        return .Ok;
    }

    public Result<void> StopServer()
    {
        DeleteContainerAndItems!(runners);

        return .Ok;
    }
}

// This class is not meant to run directly, rather copy
// this class and modify as needed!
static class Main
{
    static void Main(String[] cfgarg)
    {
        Config config = scope Config();

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
                var unamePwd = cfgarg[i].Split('=');
                config.static_credentials.Add((unamePwd.GetNext(), unamePwd.GetNext()));
            }
            else if (cfgarg[i] == "--auth-static-auth-secret")
            {
                i++;
                config.static_auth_secret = cfgarg[i];
            }
            else if (cfgarg[i] == "--log-level")
            {
                i++;
                config.log = LogLevel.FromStr(cfgarg[i]);
            }
            else if (cfgarg[i] == "--turn-realm")
            {
                i++;
                config.realm = cfgarg[i];
            }
            else if (cfgarg[i] == "--turn-interfaces")
            {
                i++;
                config.interfaces.Add(CfgInterface.FromStr(cfgarg[i]));
            }
        }

        // Add some interfaces if there is none, really should modify this section!
        if (config.interfaces.Count < 1)
        {
            config.interfaces.Add(CfgInterface()
            {
                bind = (3000, "0.0.0.0"),
                transport = .UDP
            });
            Common.FillAddressInfo(ref config.interfaces[0].external, AF_INET, "127.0.0.1", 3000);
            /*config.interfaces.Add(CfgInterface()
            {
                bind = (3000, "0.0.0.0"),
                transport = .TCP
            });
            Common.FillAddressInfo(ref config.interfaces[1].external, AF_INET, "127.0.0.1", 3000);*/
        }
        
        BeefSturn bsturn = scope BeefSturn();

        {
            Statistics statistics = scope Statistics();
            Service lservice = scope Service(
                StringView("beefsturn"),
                StringView(config.realm),
                config.get_externals(),
                scope Observer(config, statistics)
            );
        
            bsturn.StartServer(config, statistics, lservice);
        }

        String buf = scope String();
        while (buf != "q")
        {
            buf.Clear();
            Console.ReadLine(buf);
        }

        bsturn.StopServer();
    }
}
