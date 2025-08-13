namespace BeefSturn.Turn;

using System;
using System.Collections;
using System.Diagnostics;
using System.Threading;
using Beef_Net;

/// Authentication information for the session.
///
/// Digest data is data that summarises usernames and passwords by means of
/// long-term authentication.
struct TurnAuth
{
    public StringView username;
    public uint8[16] integrity;
}

/// Assignment information for the session.
///
/// Sessions are all bound to only one port and one channel.
struct Allocate : IDisposable
{
    public uint16 port;
    public List<uint16> channels;

    public this()
    {
        this = default;
        port = 0;
        channels = new List<uint16>(16);
    }

    public void Dispose()
    {
        delete channels;
    }
}

/// turn session information.
///
/// A user can have many sessions.
///
/// The default survival time for a session is 600 seconds.
struct TurnSession : IDisposable
{
    public TurnAuth auth;
    public Allocate allocate;
    public List<uint16> permissions;
    public uint64 expires;

    public this()
    {
        this = default;
        permissions = new List<uint16>(16);
    }

    public void Dispose()
    {
        delete permissions;
    }
}

/// The identifier of the session or addr.
///
/// Each session needs to be identified by a combination of three pieces of
/// information: the addr address, and the transport protocol.
struct SessionAddr : IHashable
{
    public SocketAddress address;
    public SocketAddress sainterface;

    public int GetHashCode()
    {
        int hash = 0;
        if (address.Family == AF_INET)
        {
            hash = address.u.IPv4.sin_port.GetHashCode() ^ address.u.IPv4.sin_addr.s_addr.GetHashCode();
        }
        else if (address.Family == AF_INET6)
        {
            hash = address.u.IPv6.sin6_port.GetHashCode()
                ^ address.u.IPv6.sin6_addr.u6_addr32[0].GetHashCode()
                ^ address.u.IPv6.sin6_addr.u6_addr32[1].GetHashCode()
                ^ address.u.IPv6.sin6_addr.u6_addr32[2].GetHashCode()
                ^ address.u.IPv6.sin6_addr.u6_addr32[3].GetHashCode();
        }

        if (sainterface.Family == AF_INET)
        {
            hash ^= sainterface.u.IPv4.sin_port.GetHashCode() ^ sainterface.u.IPv4.sin_addr.s_addr.GetHashCode();
        }
        else if (sainterface.Family == AF_INET6)
        {
            hash ^= sainterface.u.IPv6.sin6_port.GetHashCode()
                ^ sainterface.u.IPv6.sin6_addr.u6_addr32[0].GetHashCode()
                ^ sainterface.u.IPv6.sin6_addr.u6_addr32[1].GetHashCode()
                ^ sainterface.u.IPv6.sin6_addr.u6_addr32[2].GetHashCode()
                ^ sainterface.u.IPv6.sin6_addr.u6_addr32[3].GetHashCode();
        }

        return hash;
    }
}

/// The addr used to record the current session.
///
/// This is used when forwarding data.
struct Endpoint
{
    public SocketAddress address;
    public SocketAddress endpoint;
}

/// A specially optimised timer.
///
/// This timer does not stack automatically and needs to be stacked externally
/// and manually.
struct STTimer
{
    private uint64 timeval;

    public uint64 Timeval
    {
        get { return timeval; }
    }

    public uint64 get()
    {
        return timeval;
    }

    public uint64 add() mut
    {
        Interlocked.Increment(ref timeval, .Relaxed);

        return timeval;
    }
}

class State
{
    public Dictionary<SessionAddr, TurnSession> sessions;
    public PortAllocatePools port_allocate_pool;
    // Records the sessions corresponding to each assigned port, which will be needed when looking
    // up sessions assigned to this port based on the port number.
    public Dictionary<uint16, SessionAddr> port_mapping_table;
    // Records the nonce value for each network connection, which is independent of the session
    // because it can exist before it is authenticated.
    public Dictionary<SessionAddr, (StringView, uint64)> address_nonce_table;
    // Stores the address to which the session should be forwarded when it sends indication to a
    // port. This is written when permissions are created to allow a certain address to be
    // forwarded to the current session.
    public Dictionary<SessionAddr, Dictionary<uint16, Endpoint>> port_relay_table;
    // Indicates to which session the data sent by a session to a channel should be forwarded.
    public Dictionary<SessionAddr, Dictionary<uint16, Endpoint>> channel_relay_table;

    public RWLock sessionWrite;
    public Monitor papAccess;
    public RWLock pmtWrite;
    public RWLock antWrite;
    public RWLock prtWrite;
    public RWLock crtWrite;

    public this()
    {
        sessions = new Dictionary<SessionAddr, TurnSession>((int32)PortAllocatePools.capacity());
        port_mapping_table = new Dictionary<uint16, SessionAddr>((int32)PortAllocatePools.capacity());
        address_nonce_table = new Dictionary<SessionAddr, (StringView, uint64)>((int32)PortAllocatePools.capacity());
        port_mapping_table = new Dictionary<uint16, SessionAddr>((int32)PortAllocatePools.capacity());
        port_relay_table = new Dictionary<SessionAddr, Dictionary<uint16, Endpoint>>((int32)PortAllocatePools.capacity());
        channel_relay_table = new Dictionary<SessionAddr, Dictionary<uint16, Endpoint>>((int32)PortAllocatePools.capacity());

        sessionWrite = new RWLock();
        papAccess = new Monitor();
        pmtWrite = new RWLock();
        antWrite = new RWLock();
        prtWrite = new RWLock();
        crtWrite = new RWLock();
    }

    public this(State copyst)
    {
        sessions = new Dictionary<SessionAddr, TurnSession>(copyst.sessions.GetEnumerator());
        port_mapping_table = new Dictionary<uint16, SessionAddr>(copyst.port_mapping_table.GetEnumerator());
        address_nonce_table = new Dictionary<SessionAddr, (StringView, uint64)>(copyst.address_nonce_table.GetEnumerator());
        port_mapping_table = new Dictionary<uint16, SessionAddr>(copyst.port_mapping_table.GetEnumerator());
        port_relay_table = new Dictionary<SessionAddr, Dictionary<uint16, Endpoint>>((int32)PortAllocatePools.capacity());
        channel_relay_table = new Dictionary<SessionAddr, Dictionary<uint16, Endpoint>>((int32)PortAllocatePools.capacity());

        for (let pr in copyst.port_relay_table)
        {
            port_relay_table.Add(pr.key, new Dictionary<uint16, Endpoint>(pr.value.GetEnumerator()));
        }

        for (let cr in copyst.channel_relay_table)
        {
            channel_relay_table.Add(cr.key, new Dictionary<uint16, Endpoint>(cr.value.GetEnumerator()));
        }

        port_allocate_pool = copyst.port_allocate_pool;

        sessionWrite = new RWLock();
        papAccess = new Monitor();
        pmtWrite = new RWLock();
        antWrite = new RWLock();
        prtWrite = new RWLock();
        crtWrite = new RWLock();
    }

    public ~this()
    {
        delete sessions;
        delete port_mapping_table;
        delete address_nonce_table;
        delete port_mapping_table;
        DeleteDictionaryAndValues!(port_relay_table);
        DeleteDictionaryAndValues!(channel_relay_table);

        delete sessionWrite;
        delete papAccess;
        delete pmtWrite;
        delete antWrite;
        delete prtWrite;
        delete crtWrite;
    }

    public Result<TurnSession> getSession(SessionAddr saddr)
    {
        if (!sessions.ContainsKey(saddr))
        {
            return .Err;
        }
        TurnSession ret = sessions.GetValue(saddr);
        return .Ok(ret);
    }

    public Dictionary<SessionAddr, TurnSession>.Enumerator getAllSessions()
    {
        let sesenum = sessions.GetEnumerator();
        return sesenum;
    }

    public PortAllocatePools getPortAllocatePool()
    {
        PortAllocatePools pool = port_allocate_pool;
        return pool;
    }

    public Result<SessionAddr> getPortMapping(uint16 key)
    {
        if (!port_mapping_table.ContainsKey(key))
        {
            return .Err;
        }
        return .Ok(port_mapping_table.GetValue(key));
    }

    public Result<(StringView, uint64)> getAddressNonce(SessionAddr saddr)
    {
        if (!address_nonce_table.ContainsKey(saddr))
        {
            return .Err;
        }
        return .Ok(address_nonce_table.GetValue(saddr));
    }

    public Dictionary<SessionAddr, (StringView, uint64)>.Enumerator getAllAddressNonces()
    {
        return address_nonce_table.GetEnumerator();
    }

    public bool getPortRelay(SessionAddr saddr, ref Dictionary<uint16, Endpoint> dict)
    {
        if (!port_relay_table.ContainsKey(saddr))
        {
            return false;
        }
        dict = port_relay_table.GetValue(saddr);
        return true;
    }

    public bool getChannelRelay(SessionAddr saddr, ref Dictionary<uint16, Endpoint> dict)
    {
        if (!channel_relay_table.ContainsKey(saddr))
        {
            return false;
        }
        dict = channel_relay_table.GetValue(saddr);
        return true;
    }

    public void setSession(SessionAddr saddr, TurnSession ts)
    {
        sessions[saddr] = ts;
    }

    public void addToPortPool(uint16 port)
    {
        port_allocate_pool.restore(port);
    }

    public void setPortMapping(uint16 key, SessionAddr saddr)
    {
        port_mapping_table[key] = saddr;
    }

    public void setAddressNonce(SessionAddr saddr, StringView str, uint64 exp)
    {
        address_nonce_table[saddr] = (str, exp);
    }

    public void setPortRelay(SessionAddr saddr, uint16 port, Endpoint endp)
    {
        if (port_relay_table.GetValue(saddr) case .Err)
        {
            port_relay_table.Add(saddr, new Dictionary<uint16, Endpoint>(20));
        }
        port_relay_table[saddr][port] = endp;
    }

    public void setChannelRelay(SessionAddr saddr, uint16 chan, Endpoint endp)
    {
        if (channel_relay_table.GetValue(saddr) case .Err)
        {
            channel_relay_table.Add(saddr, new Dictionary<uint16, Endpoint>(20));
        }
        channel_relay_table[saddr][chan] = endp;
    }

    public void removeSession(SessionAddr saddr)
    {
        sessions.Remove(saddr);
    }

    public void removePortMapping(uint16 key)
    {
        port_mapping_table.Remove(key);
    }

    public void removeAddressNonce(SessionAddr saddr)
    {
        address_nonce_table.Remove(saddr);
    }

    public void removePortRelay(SessionAddr saddr)
    {
        delete port_relay_table[saddr];
        port_relay_table.Remove(saddr);
    }

    public void removeChannelRelay(SessionAddr saddr)
    {
        delete channel_relay_table[saddr];
        channel_relay_table.Remove(saddr);
    }
}

class Sessions
{
    public STTimer timer;
    public State state;
    public Observer observer;
    public bool running;
    public Random rnd;

    public this(Sessions copysess)
    {
        this.timer = copysess.timer;
        this.state = new State(copysess.state);
        this.observer = new Observer(copysess.observer);
        running = true;
        rnd = new Random();
    }

    public this(Observer observer)
    {
        state = new State();
        timer = STTimer();
        observer = observer;
        running = true;
        rnd = new Random();

        // This is a background thread that silently handles expiring sessions and
        // cleans up session information when it expires.
        Thread t = new Thread(new() =>
        {
            List<SessionAddr> address = scope List<SessionAddr>(255);

            while(running)
            {
                // The timer advances one second and gets the current time offset.
                uint64 now = timer.add();

                // This is the part that deletes the session information.
                
                // Finds sessions that have expired.
                {
                    let sess = state.getAllSessions();
                    for (let ses in sess)
                    {
                        if (ses.value.expires <= now)
                        {
                            address.Add(ses.key);
                        }
                    }
                    
                    // Delete the expired sessions.
                    if (!address.IsEmpty)
                    {
                        remove_session(address);
                        address.Clear();
                    }
                }

                // Because nonce does not follow session creation, nonce is created for each
                // addr, so nonce deletion is handled independently.
                {
                    let nonces = state.getAllAddressNonces();
                    for (let nonce in nonces)
                    {
                        if (nonce.value.1 <= now)
                        {
                            address.Add(nonce.key);
                        }
                    }

                    if (!address.IsEmpty)
                    {
                        remove_nonce(address);
                        address.Clear();
                    }
                }

                // Fixing a second tick.
                Thread.Sleep(1000);
            }
        });
    }

    public ~this()
    {
        delete observer;
        delete state;
        delete rnd;
    }

    private void remove_session(Span<SessionAddr> addrs)
    {
        state.sessionWrite.Write();
        state.papAccess.Enter();
        state.pmtWrite.Write();
        state.prtWrite.Write();
        state.crtWrite.Write();

        for (let add in addrs)
        {
            state.removePortRelay(add);
            state.removeChannelRelay(add);
            TurnSession tmpses = state.getSession(add);
            uint16 port = tmpses.allocate.port;
            state.removeSession(add);
            // Removes the session-bound port from the port binding table and
            // releases the port back into the allocation pool.
            state.removePortMapping(port);
            state.addToPortPool(port);
       
            // Notifies that the external session has been closed.
            observer.closed(add, tmpses.auth.username);
        }

        state.sessionWrite.ExitWrite();
        state.papAccess.Exit();
        state.pmtWrite.ExitWrite();
        state.prtWrite.ExitWrite();
        state.crtWrite.ExitWrite();
    }

    private void remove_nonce(Span<SessionAddr> addrs)
    {
        state.antWrite.Write();
        for (let nonce in addrs)
        {
            state.removeAddressNonce(nonce);
        }
        state.antWrite.ExitWrite();
    }

    /// Get session for addr.
    public TurnSession get_session(SessionAddr key)
    {
        state.sessionWrite.Read();
        TurnSession ses = state.getSession(key);
        state.sessionWrite.ExitRead();
        return ses;
    }

    /// Get nonce for addr.
    public (StringView, uint64) get_nonce(SessionAddr key)
    {
        state.antWrite.Read();
        // If no nonce is created, create a new one.
        let nonceRes = state.getAddressNonce(key);
        state.antWrite.ExitRead();
        if (nonceRes case .Err)
        {
            state.antWrite.Write();
            // A random string of length 16.
            uint8[] bt = scope uint8[16]();
            rnd.NextBytes(bt);
            String randomStr = scope String((char8*)bt.Ptr, 16);
            uint64 time = timer.Timeval + 600;
            
            state.setAddressNonce(key, randomStr, time);
            state.antWrite.ExitWrite();
            return (randomStr, time);
        }

        return nonceRes.Value;
    }

    /// Get digest for addr.
    public uint8[16] get_integrity(SessionAddr addr, StringView username, StringView realm)
    {
        // Already authenticated, get the cached digest directly.
        {
            state.sessionWrite.Read();
            let sesState = state.getSession(addr);
            state.sessionWrite.ExitRead();
            if (sesState case .Ok(let session))
            {    
                return session.auth.integrity;
            }
        }

        // Get the current user's password from an external observer and create a
        // digest.
        let password = observer.get_password(username);
        uint8[16] integrity = Stun.long_term_credential_digest(username, password, realm);

        // Record a new session.
        {
            state.sessionWrite.Write();
            state.setSession(addr, TurnSession()
            {
                expires = timer.get() + 600,
                auth = TurnAuth()
                {
                    username = username,
                    integrity = integrity
                },
                allocate = Allocate()
            });
            state.sessionWrite.ExitWrite();
        }

        return integrity;
    }

    public uint64 allocated()
    {
        state.papAccess.Enter();
        uint64 ports = state.getPortAllocatePool().len();
        state.papAccess.Exit();
        return ports;
    }

    /// Assign a port number to the session.
    public uint16 allocate(SessionAddr addr)
    {
        state.sessionWrite.Write();
        TurnSession ses;
        if (!(state.getSession(addr) case .Ok(out ses)))
        {
            state.sessionWrite.ExitWrite();
            return 0;
        }

        // If the port has already been allocated, re-allocation is not allowed.
        if (ses.allocate.port > 0)
        {
            state.sessionWrite.ExitWrite();
            return ses.allocate.port;
        }

        // Records the port assigned to the current session and resets the alive time.
        state.papAccess.Enter();
        uint16 port = state.getPortAllocatePool().alloc();
        state.papAccess.Exit();
        ses.expires = timer.get() + 600;
        ses.allocate.port = port;
        state.setSession(addr, ses);

        // Write the allocation port binding table.
        state.pmtWrite.Write();
        state.setPortMapping(port, addr);
        state.pmtWrite.ExitWrite();
        state.sessionWrite.ExitWrite();
        return port;
    }

    /// Create permission for session.
    public bool create_permission(SessionAddr addr, SocketAddress endpoint, Span<uint16> ports)
    {
        state.sessionWrite.Write();
        state.prtWrite.Write();
        state.pmtWrite.Read();
        // Finds information about the current session.
        TurnSession session;
        if (!(state.getSession(addr) case .Ok(out session)))
        {
            state.sessionWrite.ExitWrite();
            state.prtWrite.ExitWrite();
            state.pmtWrite.ExitRead();
            return false;
        }

        // The port number assigned to the current session.
        uint16 local_port = session.allocate.port;
        if (local_port < 1)
        {
            state.sessionWrite.ExitWrite();
            state.prtWrite.ExitWrite();
            state.pmtWrite.ExitRead();
            return false;
        }

        // You cannot create permissions for yourself.
        if (ports.IndexOf(local_port) > -1)
        {
            state.sessionWrite.ExitWrite();
            state.prtWrite.ExitWrite();
            state.pmtWrite.ExitRead();
            return false;
        }

        // Each peer port must be present.
        List<(uint16, SessionAddr)> peers = scope List<(uint16, SessionAddr)>(15);
        for (uint16 port in ports)
        {
            if (state.getPortMapping(port) case .Ok(let mappin))
            {
                peers.Add((port, mappin));
            }
            else
            {
                state.sessionWrite.ExitWrite();
                state.prtWrite.ExitWrite();
                state.pmtWrite.ExitRead();
                return false;
            }
        }

        // Create a port forwarding mapping relationship for each peer session.
        for (let portNPeer in peers)
        {
            state.setPortRelay(portNPeer.1, local_port, Endpoint() {
                address = addr.address,
                endpoint = endpoint
            });

            // Do not store the same peer ports to the permission list over and over again.
            if (!session.permissions.Contains(portNPeer.0))
            {
                session.permissions.Add(portNPeer.0);
            }
        }

        state.setSession(addr, session);

        state.sessionWrite.ExitWrite();
        state.prtWrite.ExitWrite();
        state.pmtWrite.ExitRead();
        return true;
    }

    /// Binding a channel to the session.
    public bool bind_channel(SessionAddr addr, SocketAddress endpoint, uint16 port, uint16 channel)
    {
        // Finds the address of the bound opposing port.
        state.pmtWrite.Read();
        let peer = state.getPortMapping(port);
        state.pmtWrite.ExitRead();

        if (!(peer case .Ok))
        {
            return false;
        }

        // Records the channel used for the current session.
        {
            state.sessionWrite.Write();
            let sessionRes = state.getSession(addr);

            if (sessionRes case .Ok(let session))
            {
                if (session.allocate.channels.Contains(channel))
                {
	                session.allocate.channels.Add(channel);
                }
                state.setSession(addr, session);
            }
            else
            {
                state.sessionWrite.ExitWrite();
                return false;
            }
            state.sessionWrite.ExitWrite();
        }

        // Binding ports also creates permissions.
        if (!create_permission(addr, endpoint, Span<uint16>(new uint16[](port))))
        {
            return false;
        }

        // Create channel forwarding mapping relationships for peers.
        state.crtWrite.Write();
        state.setChannelRelay(peer, channel, Endpoint()
        {
            address = addr.address,
            endpoint = endpoint
        });
        state.crtWrite.ExitWrite();

        return true;
    }

    /// Gets the peer of the current session bound channel.
    public Endpoint? get_channel_relay_address(SessionAddr addr, uint16 channel)
    {
        state.crtWrite.Read();
        Dictionary<uint16, Endpoint> outDict = scope Dictionary<uint16, Endpoint>();
        if (!state.getChannelRelay(addr, ref outDict))
        {
            state.crtWrite.ExitRead();
            return null;
        }
        state.crtWrite.ExitRead();
        return outDict.GetValue(channel);
    }

    /// Get the address of the port binding.
    public Endpoint? get_relay_address(SessionAddr addr, uint16 port)
    {
        state.prtWrite.Read();
        Dictionary<uint16, Endpoint> outDict = scope Dictionary<uint16, Endpoint>();
        if (!state.getPortRelay(addr, ref outDict))
        {
            state.prtWrite.ExitRead();
            return null;
        }
        state.prtWrite.ExitRead();
        return outDict.GetValue(port);
    }

    /// Refresh the session for addr.
    public bool refresh(SessionAddr addr, uint32 lifetime)
    {
        if (lifetime > 3600)
        {
            return false;
        }

        if (lifetime == 0)
        {
            remove_session(Span<SessionAddr>(new SessionAddr[](addr)));
            remove_nonce(Span<SessionAddr>(new SessionAddr[](addr)));
        }
        else
        {
            state.sessionWrite.Write();
            if (state.getSession(addr) case .Ok(var session))
            {
                session.expires = timer.get() + lifetime;
                state.setSession(addr, session);
            }
            else
            {
                state.sessionWrite.ExitWrite();
                return false;
            }

            state.antWrite.Write();
            if (state.getAddressNonce(addr) case .Ok(var nonce))
            {
                nonce.1 = timer.get() + lifetime;
                state.setAddressNonce(addr, nonce.0, nonce.1);
            }
        }

        return true;
    }
}


/// Bit Flag
enum Bit
{
    Low,
    High
}

/// Random Port
///
/// Recently, awareness has been raised about a number of "blind" attacks
/// (i.e., attacks that can be performed without the need to sniff the
/// packets that correspond to the transport protocol instance to be
/// attacked) that can be performed against the Transmission Control
/// Protocol (TCP) [RFC0793] and similar protocols.  The consequences of
/// these attacks range from throughput reduction to broken connections
/// or data corruption [RFC5927] [RFC4953] [Watson].
///
/// All these attacks rely on the attacker's ability to guess or know the
/// five-tuple (Protocol, Source Address, Source port, Destination
/// Address, Destination Port) that identifies the transport protocol
/// instance to be attacked.
///
/// Services are usually located at fixed, "well-known" ports [IANA] at
/// the host supplying the service (the server).  Client applications
/// connecting to any such service will contact the server by specifying
/// the server IP address and service port number.  The IP address and
/// port number of the client are normally left unspecified by the client
/// application and thus are chosen automatically by the client
/// networking stack.  Ports chosen automatically by the networking stack
/// are known as ephemeral ports [Stevens].
///
/// While the server IP address, the well-known port, and the client IP
/// address may be known by an attacker, the ephemeral port of the client
/// is usually unknown and must be guessed.
///
struct PortAllocatePools : IDisposable
{
    public List<uint64> buckets;
    public uint64 allocated;
    public uint32 bit_len;
    public int peak;
    Random rnd;

    public this()
    {
        this = default;
        buckets = new List<uint64>(bucket_size());
        peak = bucket_size() - 1;
        bit_len = bit_len();
        allocated = 0;
        rnd = new Random();
    }

    public void Dispose()
    {
        delete buckets;
        delete rnd;
    }

    /// compute bucket size.
    public uint32 bucket_size()
    {
        return (uint32)Math.Ceiling(capacity() / 64.0);
    }

    /// compute bucket last bit max offset.
    public uint32 bit_len()
    {
        return (uint32)Math.Ceiling(capacity() % 64.0);
    }

    /// get pools capacity.
    public static uint32 capacity()
    {
        return 65535 - 49152;
    }

    /// get port range.
    public (uint16, uint16) port_range()
    {
        return (49152, 65535);
    }

    /// get pools allocated size.
    public uint64 len()
    {
        return allocated;
    }

    /// get pools allocated size is empty.
    public bool is_empty()
    {
        return allocated == 0;
    }

    /// random assign a port.
    public uint16 alloc() mut
    {
        return alloc(null);
    }
    public uint16 alloc(int? start_index) mut
    {
        int? index = null;
        int start = 0;
        if (start_index.HasValue)
        {
            start = start_index.Value;
        }
        else
        {
            start = rnd.NextI32() % peak;
        }

        // When the partition lookup has gone through the entire partition list, the
        // lookup should be stopped, and the location where it should be stopped is
        // recorded here.
        int previous = start == 0 ? (int)peak : start - 1;

        while(start != previous)
        {
            // Finds the first high position in the partition.
            uint64 bucket = buckets[start];

            if (bucket < UInt64.MaxValue)
            {
                int offset = 0;

                for (int i = 63; i >= 0; i--)
                {
                    if ((bucket & (1UL << i)) != 0)
                    {
                        offset++;
                    }
                    else
                    {
                        break;
                    }
                }

                // Check to see if the jump is beyond the partition list or the lookup exceeds
                // the maximum length of the allocation table.
                if (!(start == peak && offset > bit_len))
                {
                    index = null;
                }
                else
                {
                    index = offset;
                    break;
                }
            }
            else
            {
                index = null;
            }

            // As long as it doesn't find it, it continues to re-find it from the next
            // partition.
            if (start == peak)
            {
                start = 0;
            }
            else
            {
                start += 1;
            }

            // Already gone through all partitions, lookup failed.
            if (start == previous)
            {
                break;
            }
        }

        // Writes to the partition, marking the current location as already allocated.
        set_bit(start, index.Value, Bit.High);
        allocated += 1;

        // The actual port number is calculated from the partition offset position.
        uint16 num = (uint16)(start * 64 + index);
        uint16 port = port_range().0 + num;
        return port;
    }

    /// write bit flag in the bucket.
    public void set_bit(int bucket, int index, Bit bit)
    {
        uint64 high_mask = 1 << (63 - index);
        uint64 mask = 0;
        if (bit == Bit.Low)
        {
            mask = UInt64.MaxValue ^ high_mask;
        }
        else
        {
            mask = high_mask;
        }

        uint64 value = buckets[bucket];
        if (bit == Bit.Low)
        {
            buckets[bucket] = value & mask;
        }
        else
        {
            buckets[bucket] = value | mask;
        }
    }

    /// restore port in the buckets.
    public bool restore(uint16 port) mut
    {
        Debug.Assert(port >= port_range().0 && port <= port_range().1);

        // Calculate the location in the partition from the port number.
        uint16 offset = (port - port_range().0);
        int bucket = offset / 64;
        int index = offset - (bucket * 64);

        // Gets the bit value in the port position in the partition, if it is low, no
        // processing is required.
        uint64 matchVal = buckets[bucket] & (1 << (63 - index)) >> (63 - index);
        if (matchVal == 0)
        {
            return true;
        }
        else if (matchVal != 1)
        {
            return false;
        }
        
        set_bit(bucket, index, Bit.Low);
        allocated -= 1;
        return true;
    }
}
