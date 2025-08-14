namespace BeefSturn;

using System;
using System.Collections;
using BeefSturn.Turn;

class BeefSturn
{
    private List<Server> runners;
    private Service service;

    public Result<void> StartServer(Config config)
    {
        Statistics statistics = Statistics();
        Service lservice = scope Service(
            "beefsturn",
            config.turn.realm,
            config.turn.get_externals(),
            scope Observer(config, statistics)
        );

        StartServer(config, statistics, lservice);

        // The turn server is non-blocking after it runs and needs to be kept from
        // exiting immediately if the api server is not enabled.

        return .Ok;
    }

    
    /// start turn server.
    ///
    /// create a specified number of threads,
    /// each thread processes udp data separately.
    public Result<void> StartServer(Config config, Statistics statistics, Service lservice)
    {
        Router router = Router();

        runners = new List<Server>();
        service = new Service();

        for (let intobj in config.turn.interfaces)
        {
            //transport,
            //external,
            //bind,
        
            ServerStartOptions options = ServerStartOptions()
            {
                statistics = statistics,
                service = service,
                router = router,
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

    public Result<void> stop()
    {
        DeleteContainerAndItems!(runners);
        delete service;

        return .Ok;
    }
}

static class Main
{
    static void Main(String[] args)
    {
        Config config = Config();
        BeefSturn bsturn = new BeefSturn();
    
        bsturn.StartServer(config);
    }
}
