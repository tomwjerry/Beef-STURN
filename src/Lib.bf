namespace BeefSturn;

using System;
using BeefSturn.Turn;

/// In order to let the integration test directly use the turn-server crate and
/// start the server, a function is opened to replace the main function to
/// directly start the server.
static class Lib
{
    public static Result<void> startup(Config config)
    {
        Statistics statistics = Statistics();
        Service service = new Service(
            "beefsturn",
            config.turn.realm,
            config.turn.get_externals(),
            scope Observer(config, statistics)
        );
    
        StartServer(config, statistics, service);
    
        // The turn server is non-blocking after it runs and needs to be kept from
        // exiting immediately if the api server is not enabled.
    
        return .Ok;
    }
}
