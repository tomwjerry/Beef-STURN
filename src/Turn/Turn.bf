namespace BeefSturn.Turn;

using System;
using System.Collections;
using Beef_Net;
using BeefSturn.Turn.Operations;

class Service
{
    public List<SocketAddress> interfaces;
    public Sessions sessions;
    public StringView software;
    public StringView realm;
    public Observer observer;

    public this()
    {
        interfaces = new List<SocketAddress>();
        observer = new Observer(scope Config(), scope Statistics());
        sessions = new Sessions(observer);
    }

    /// Create turn service.
    public this(StringView software, StringView realm, Span<SocketAddress> interfaces, Observer observer)
    {
        this.software = software;
        this.realm = realm;
        this.interfaces = new List<SocketAddress>(interfaces);
        this.observer = new Observer(observer);
        this.sessions = new Sessions(observer);
    }

    public this(Service copyser)
    {
        this.software = copyser.software;
        this.realm = copyser.realm;
        this.interfaces = new List<SocketAddress>(copyser.interfaces);
        this.observer = new Observer(copyser.observer);
        this.sessions = new Sessions(copyser.sessions);
    }

    public ~this()
    {
        delete interfaces;
        delete sessions;
        delete observer;
    }

    public void get_sessions(out Sessions s)
    {
        s = sessions;
    }

    /// Get operationer.
    public ServiceContext get_serviceContext(SocketAddress endpoint, SocketAddress sainterface)
    {
        ServiceContext sc = ServiceContext(interfaces, observer, sessions);
        sc.software = software;
        sc.realm = realm;
        sc.sainterface = sainterface;
        sc.endpoint = endpoint;

        return sc;
    }
}
