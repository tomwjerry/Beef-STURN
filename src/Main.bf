namespace BeefSturn;

using System;

static class Main
{
    static void Main(String[] args)
    {
        Config config = Config();
    
        turn_server.startup(config);
    }
}
