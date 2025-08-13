namespace BeefSturn;

using System;
using BeefSturn.Turn;
using Beef_Net;

struct ApiState : IDisposable
{
    public Config config;
    public Service service;
    public Statistics statistics;
    public DateTime uptime;

    public void Dispose()
    {
        delete service;
        statistics.Dispose();
    }
}

struct QueryParams
{
    public SocketAddress address;
    public SocketAddress sainterface;

    public SessionAddr into()
    {
        return SessionAddr()
        {
            address = address,
            sainterface = sainterface
        };
    }
}

struct EventData
{

}

struct Events : IDisposable
{
    public Event<delegate void(StringView, EventData)> CHANNEL;

    public void Dispose() mut
    {
        CHANNEL.Dispose();
    }

    public Event<delegate void(StringView, EventData)> get_event_stream()
    {
        return CHANNEL;
    }

    public void send_with_stream(StringView event, delegate EventData() handle) mut
    {
        if (CHANNEL.Count > 0)
        {
            CHANNEL(event, handle());
        }
    }
}
