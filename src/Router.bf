namespace BeefSturn;

using System;
using System.Collections;
using Beef_Net;
using Beef_Net.Connection;
using BeefSturn.Turn.Operations;

struct Receiver
{
    public Span<uint8> data;
    public ResponseMethod respMethod;
    public Socket sock;
}

/// Handles packet forwarding between transport protocols.
struct Router : IDisposable
{
    Dictionary<SocketAddress, Receiver> socketRecv;
    RWLock routerLock;

    public this()
    {
        socketRecv = new Dictionary<SocketAddress, Receiver>(1024);
        routerLock = new RWLock();
    }

    public void Dispose()
    {
        delete routerLock;
        delete socketRecv;
    }

    /// Get the socket reader for the route.
    ///
    /// Each transport protocol is layered according to its own socket, and
    /// the data forwarded to this socket can be obtained by routing.
    public Receiver get_receiver(SocketAddress sainterface)
    {
        using (routerLock.Write())
        {
            if (!socketRecv.ContainsKey(sainterface))
            {
                socketRecv.Add(sainterface, Receiver());
            }
        }

        return socketRecv.GetValue(sainterface);
    }

    /// Send data to router.
    ///
    /// By specifying the socket identifier and destination address, the route
    /// is forwarded to the corresponding socket. However, it should be noted
    /// that calling this function will not notify whether the socket exists.
    /// If it does not exist, the data will be discarded by default.
    public void send(SocketAddress sainterface, ResponseMethod method, SocketAddress toWhere, Span<uint8> data)
    {
        bool is_destroy = false;

        using (routerLock.Read())
        {
            if (socketRecv.TryGetValue(sainterface, let sender))
            {
                if (sender.sock.Send(data.Ptr, (int32)data.Length, toWhere) < 0)
                {
                    is_destroy = true;
                }
            }
        }

        if (is_destroy)
        {
            remove(sainterface);
        }
    }

    /// delete socket.
    public void remove(SocketAddress sainterface)
    {
        using(routerLock.Write())
        {
            // Close connection?
            socketRecv.Remove(sainterface);
        }
    }
}
