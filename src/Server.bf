namespace BeefSturn;

using System;
using System.Collections;
using System.Threading;
using System.Diagnostics;
using Beef_Net;
using Beef_Net.Connection;
using BeefSturn.Stun;
using BeefSturn.Turn;
using BeefSturn.Turn.Operations;

class ServerStartOptions
{
    public (uint16, StringView) bind;
    public SocketAddress external;
    public Service service;
    public Router router;
    public Statistics statistics;

    public ~this()
    {
        delete service;
        delete router;
        delete statistics;
    }
}

interface Server
{
    public Result<void, StringView> start(ServerStartOptions options);
}

class SturnUDP : Server
{
    Thread recvThread;
    Thread sendThread;
    UdpConnection socket;
    bool running;

    Router router;
    Operationer operationer;
    SessionAddr session_addr;
    SocketAddress external;
    Statistics statistics;
    /// udp socket process thread.
    ///
    /// read the data packet from the UDP socket and hand
    /// it to the proto for processing, and send the processed
    /// data packet to the specified address.

    public Result<void, StringView> start(ServerStartOptions options)
    {
        socket = new UdpConnection();
        socket.Listen(options.bind.0, options.bind.1);

        router = new Router(options.router);
        ServiceContext sc = scope ServiceContext();
        options.service.get_serviceContext(options.external, options.external, sc);
        operationer = new Operationer(sc);
        external = options.external;
        statistics = new Statistics(options.statistics);

        session_addr = SessionAddr()
        {
            address = options.external,
            sainterface = options.external
        };

        running = true;

        recvThread = new Thread(new => recvThreadFun);
        sendThread = new Thread(new => sendThreadFun);
        recvThread.Start();
        sendThread.Start();

        Log.Info(
            "turn server listening: bind={}, external={}, transport=UDP",
            options.bind,
            options.external
        );

        return .Ok;
    }

    private void recvThreadFun()
    {
        uint8[2048] buf = uint8[2048](0,);
        StatisticsReporter reporter = scope StatisticsReporter(statistics.statsDict.GetEnumerator(), Transport.UDP);

        while (running)
        {
            // Note: An error will also be reported when the remote host is
            // shut down, which is not processed yet, but a
            // warning will be issued.
            int32 recvCode = socket.Get(&buf, 2048);
            if (recvCode <= 0)
            {
                continue;
            }
            else if (!Socket.IsPipeError(recvCode))
            {
                break;
            }

            session_addr.address = socket.Iterator.PeerAddress;

            reporter.send(session_addr, Span<Stats>(new Stats[](Stats.ReceivedBytes((uint64)recvCode), Stats.ReceivedPkts(1))));

            // The stun message requires at least 4 bytes. (currently the
            // smallest stun message is channel data,
            // excluding content)
            if (buf[0] > 0 || buf[1] > 0 || buf[2] > 0 || buf[3] > 0)
            {
                if (operationer.route(Span<uint8>(&buf, recvCode), session_addr.address) case .Ok(let res))
                {
                    SocketAddress target = session_addr.address;
                    if (res.relay.TryGetValue(let rl))
                    {
                        target = rl;
                    }
                    if (res.endpoint.TryGetValue(let endpoint))
                    {
                        router.send(endpoint, res.method, target, res.bytes);
                    }
                    else
                    {
                        int32 errcod = 1;
                        if ((errcod = socket.Send(res.bytes.Ptr, (int32)res.bytes.Length, target)) < 0)
                        {
                            if (!Socket.IsPipeError(errcod))
                            {
                                break;
                            }
                        }

                        reporter
                            .send(session_addr, Span<Stats>(new Stats[](Stats.SendBytes((uint64)res.bytes.Length), Stats.SendPkts(1))));

                        if (res.method case ResponseMethod.Stun(let method))
                        {
                            if (method.is_error())
                            {
                                reporter.send(session_addr, Span<Stats>(new Stats[](Stats.ErrorPkts(1))));
                            }
                        }
                    }
                }
            }
        }
    }

    private void sendThreadFun()
    {
        SessionAddr session_addr = SessionAddr()
        {
            address = external,
            sainterface = external
        };

        StatisticsReporter reporter = scope StatisticsReporter(statistics.statsDict.GetEnumerator(), Transport.UDP);
        Receiver receiver = router.get_receiver(external, socket.Iterator);
        String locadd = scope String();
        receiver.sock.GetLocalAddress(locadd);
        uint8[2048] buf = uint8[2048](0,);
        while (running)
        {
            int32 size = receiver.sock.Get(&buf, 2048);
            if (size < 1)
            {
                continue;
            }
            String addr = scope String();
            receiver.sock.GetPeerAddress(addr);
            session_addr.address = ParseSocketAddress(addr);
            int32 res = socket.Send(&buf, size);

            if (!Socket.IsPipeError(res))
            {
                break;
            }

            if (res >= 0)
            {
                reporter.send(session_addr, Span<Stats>(new Stats[](Stats.SendBytes((uint64)size), Stats.SendPkts(1))));
            }
        }

        router.remove(external);

        Log.Error("udp server close: interface={}", locadd);
    }

    public ~this()
    {
        running = false;
        sendThread.Join();

        socket.Disconnect();
        
        delete socket;
        //delete recvThread;
        //delete sendThread;

        delete router;
        delete operationer;
        delete statistics;
    }
}

class SturnTCP : Server
{
    const uint8[8] ZERO_BYTS = uint8[8](0,);

    /// An emulated double buffer queue, this is used when reading data over
    /// TCP.
    ///
    /// When reading data over TCP, you need to keep adding to the buffer until
    /// you find the delimited position. But this double buffer queue solves
    /// this problem well, in the queue, the separation is treated as the first
    /// read operation and after the separation the buffer is reversed and
    /// another free buffer is used for writing the data.
    ///
    /// If the current buffer in the separation after the existence of
    /// unconsumed data, this time the unconsumed data will be copied to another
    /// free buffer, and fill the length of the free buffer data, this time to
    /// write data again when you can continue to fill to the end of the
    /// unconsumed data.
    ///
    /// This queue only needs to copy the unconsumed data without duplicating
    /// the memory allocation, which will reduce a lot of overhead.
    class ExchangeBuffer
    {
        public (List<uint8>, int)[2] buffers;
        public uint8 index;
    
        public this()
        {
            index = 0;
            buffers[0].0 = new List<uint8>(2048);
            buffers[0].1 = 0;
            buffers[1].0 = new List<uint8>(2048);
            buffers[1].1 = 0;
        }

        public ~this()
        {
            delete buffers[0].0;
            delete buffers[1].0;
        }

        public Span<uint8> deref()
        {
            return buffers[index].0;
        }

        // Writes need to take into account overwriting written data, so fetching the
        // writable buffer starts with the internal cursor.
        public void deref_mut(ref uint8* mutref)
        {
            mutref = &buffers[index].0.Ptr[buffers[index].1];
        }

        public int len()
        {
            return buffers[index].1;
        }

        /// The buffer does not automatically advance the cursor as Bytes
        /// does, and you need to manually advance the length of the data
        /// written.
        public void advance(int len)
        {
            buffers[index].1 += len;
        }

        public Span<uint8> split(int len)
        {
            // The length of the separation cannot be greater than the length of the data.
            Debug.Assert(len <= buffers[index].1);

            uint8 oleindex = index;
            // Length of unconsumed data
            int remaining = buffers[index].1 - len;

            {
                // The current buffer is no longer in use, resetting the content length.
                buffers[index].1 = 0;

                // Invert the buffer.
                index = index == 0 ? 1 : 0;

                // The length of unconsumed data needs to be updated into the reversed
                // completion buffer.
                buffers[index].1 = remaining;
            }

            // Unconsumed data exists and is copied to the free buffer.
            if (remaining > 0)
            {
                buffers[oleindex].0.CopyTo(len, buffers[index].0, 0, buffers[oleindex].1 - len);
            }

            return buffers[oleindex].0.GetRange(0, len);
        }
    }

    struct SocketThread
    {
        public Thread thread;
        public Monitor mon;
        public Receiver receiver;
        public Operationer operationer;
        public bool running;
    }

    private Thread listenerThreadObj;
    private TcpConnection listener;
    private bool running;

    private Router router;
    private StatisticsReporter reporter;
    private Service service;
    private SocketAddress external;
    private Statistics statistics;

    private List<SocketThread> socketThreads;

    /// tcp socket process thread.
    ///
    /// This function is used to handle all connections coming from the tcp
    /// listener, and handle the receiving, sending and forwarding of messages.
    public Result<void, StringView> start(ServerStartOptions options)
    {
        listener = new TcpConnection();
        listener.Listen(options.bind.0, options.bind.1);
        listener.OnAccept = new => acceptConnection;
        listener.OnDisconnect = new => disconnectClient;
        socketThreads = new List<SocketThread>();

        router = new Router(options.router);
        reporter = new StatisticsReporter(options.statistics.statsDict.GetEnumerator(), Transport.TCP);
        external = options.external;
        service = new Service(options.service);
        service.sessions.Start();
        statistics = new Statistics(options.statistics);

        running = true;

        listenerThreadObj = new Thread(new => listenerThread);
        listenerThreadObj.Start();

        Log.Info(
            "turn server listening: bind={}, external={}, transport=TCP",
            options.bind,
            external
        );

        return .Ok;
    }

    private void listenerThread()
    {
        // Accept all connections on the current listener, but exit the entire
	    // process when an error occurs.
	    while (running)
        {
            listener.CallAction();
        }

        Log.Error("tcp server close: interface={}", listener.Iterator.LocalAddress);
    }

    private void acceptConnection(Socket aSocket)
    {
        Log.Info("tcp socket accept: addr={:?}, interface={?}", aSocket.PeerAddress, listener.Iterator.LocalAddress);

        // Disable the Nagle algorithm.
        // because to maintain real-time, any received data should be processed
        // as soon as possible.
        aSocket.SetBlocking(false);

        ServiceContext handlerContext = scope ServiceContext();
        service.get_serviceContext(aSocket.PeerAddress, external, handlerContext);
        socketThreads.Add(SocketThread()
        {
            thread = new Thread(new () => { messageHandlerThread(socketThreads.Count); }),
            mon = new Monitor(),
            receiver = router.get_receiver(aSocket.PeerAddress, aSocket),
            operationer = new Operationer(handlerContext),
            running = true
        });
        socketThreads[socketThreads.Count - 1].thread.Start();

        ServiceContext readerContext = scope ServiceContext();
        service.get_serviceContext(aSocket.PeerAddress, external, readerContext);
        socketThreads.Add(SocketThread()
        {
            thread = new Thread(new () => { messageReaderThread(socketThreads.Count); }),
            mon = new Monitor(),
            receiver = router.get_receiver(aSocket.PeerAddress, aSocket),
            operationer = new Operationer(readerContext),
            running = true
        });
        socketThreads[socketThreads.Count - 1].thread.Start();
    }

    private void messageHandlerThread(int sockThreadIdx)
    {
        Receiver receiver = socketThreads[sockThreadIdx].receiver;
        uint8[2048] buf = uint8[2048](0,);
        SessionAddr session_addr = SessionAddr()
        {
            sainterface = external,
            address = receiver.sock.PeerAddress
        };
        // Use a separate task to handle messages forwarded to this socket.
        while (running && socketThreads[sockThreadIdx].running)
        {
            int32 buflen = receiver.sock.Get(&buf, 2048);
            if (buflen < 1)
            {
                continue;
            }

            using (socketThreads[sockThreadIdx].mon.Enter())
            {
                if (socketThreads[sockThreadIdx].receiver.sock.Send(&buf, buflen) < 0)
                {
                    break;
                }
                else
                {
                    reporter.send(session_addr,
                        Span<Stats>(new Stats[](Stats.SendBytes((uint64)buflen), Stats.SendPkts(1))));
                }
            }

            // The channel data needs to be aligned in multiples of 4 in
            // tcp. If the channel data is forwarded to tcp, the alignment
            // bit needs to be filled, because if the channel data comes
            // from udp, it is not guaranteed to be aligned and needs to be
            // checked.
            if (receiver.respMethod case ResponseMethod.ChannelData)
            {
                int32 pad = buflen % 4;
                Span<uint8> zerospan = Span<uint8>(new uint8[4](0,));
                if (pad > 0 && socketThreads[sockThreadIdx].receiver.sock.Send(zerospan.Slice(4 - pad).Ptr, 4 - pad) <= 0)
                {
                    break;
                }
            }
        }
    }

    private void messageReaderThread(int sockThreadIdx)
    {
        Sessions ses;
        service.get_sessions(out ses);
        ExchangeBuffer buffer = scope ExchangeBuffer();
        SocketAddress address = socketThreads[sockThreadIdx].receiver.sock.PeerAddress;
        SessionAddr session_addr = SessionAddr()
        {
            sainterface = external,
            address = address
        };

        while (running && socketThreads[sockThreadIdx].running)
        {
            int32 msize = socketThreads[sockThreadIdx].receiver.sock.Get(buffer.buffers[buffer.index].0.Ptr, 2048);

            if (msize < 1)
            {
                continue;
            }

            reporter.send(session_addr, Span<Stats>(new Stats[](Stats.ReceivedBytes((uint64)msize))));
            buffer.advance(msize);

            // The minimum length of a stun message will not be less
            // than 4.
            if (buffer.len() < 4)
            {
                continue;
            }

            while (running && buffer.len() > 4 && socketThreads[sockThreadIdx].running)
            {
                int bsize = 0;
                // Try to get the message length, if the currently
                // received data is less than the message length, jump
                // out of the current loop and continue to receive more
                // data.
                if (Decoder.message_size(buffer.deref(), true) case .Ok(let size))
                {
                    // Limit the maximum length of messages to 2048, this is to prevent buffer
	                // overflow attacks.
                    if (size > 2048 && size > (uint64)buffer.len())
                    {
                        break;
                    }

                    reporter.send(session_addr, Span<Stats>(new Stats[](Stats.ReceivedPkts(1))));

                    bsize = (int)size;
                }
                else
                {
                    break;
                }

                Span<uint8> chunk = buffer.split(bsize);
                if (socketThreads[sockThreadIdx].operationer.route(chunk,
                    address) case .Ok(let resp))
                {
                    
                    if (resp.endpoint.HasValue)
                    {
                        router.send(
                            resp.endpoint.Value,
                            resp.method,
                            resp.relay.HasValue ? resp.relay.Value : address,
                            resp.bytes
                        );
                    }
                    else
                    {
                        using (socketThreads[sockThreadIdx].mon.Enter())
                        {
                            if (socketThreads[sockThreadIdx].receiver.sock.Send(resp.bytes.Ptr, (int32)resp.bytes.Length) < 0)
                            {
                                break;
                            }

                            reporter.send(
                                session_addr,
                                Span<Stats>(new Stats[](Stats.SendBytes((uint64)resp.bytes.Length), Stats.SendPkts(1)))
                            );

                            if (resp.method case ResponseMethod.Stun(let method))
                            {
                                if (method.is_error())
                                {
                                    reporter.send(session_addr, Span<Stats>(new Stats[](Stats.ErrorPkts(1))));
                                }
                            }
                        }
                    }
                }
                else
                {
                    break;
                }
            }
        }

        // When the tcp connection is closed, the procedure to close the session is
        // process directly once, avoiding the connection being disconnected
        // directly without going through the closing
        // process.
        ses.refresh(session_addr, 0);

        router.remove(address);

        Log.Info("tcp socket disconnect: addr={?}, interface={?}", address, socketThreads[sockThreadIdx].receiver.sock.LocalAddress);
    }

    private void disconnectClient(Socket dissocket)
    {
        for (int i = socketThreads.Count - 1; i >= 0; i--)
        {
            if (socketThreads[i].receiver.sock == dissocket)
            {
                socketThreads[i].running = false;
                delete socketThreads[i].mon;
                socketThreads[i].thread.Join();
                delete socketThreads[i].thread;
                delete socketThreads[i].operationer;
                socketThreads.RemoveAt(i);
            }
        }
    }

    public ~this()
    {
        running = false;
        listener.Disconnect();

        for (int i = socketThreads.Count - 1; i >= 0; i--)
        {
            socketThreads[i].running = false;
            delete socketThreads[i].mon;
            socketThreads[i].thread.Join();
            //delete socketThreads[i].thread;
            delete socketThreads[i].operationer;
            socketThreads.RemoveAt(i);
        }

        delete socketThreads;
        listenerThreadObj.Join();
        //delete listenerThreadObj;

        delete listener;

        delete router;
        delete reporter;
        delete statistics;
    }
}
