namespace BeefSturn;

using System;
using System.Collections;
using System.Threading;

/// The type of information passed in the statisticsing channel
enum Stats
{
    case ReceivedBytes(uint64 val);
    case SendBytes(uint64 val);
    case ReceivedPkts(uint64 val);
    case SendPkts(uint64 val);
    case ErrorPkts(uint64 val);
}

interface Number
{
    public void add(uint64 value);
    public uint64 get();
}

class Count : Number
{
    private uint64 num;

    public void add(uint64 value)
    {
        Interlocked.Add(ref num, value, .Relaxed);
    }
    public uint64 get()
    {
        return num;
    }
}

/// Worker independent statisticsing statistics
class Counts
{
    public Number received_bytes;
    public Number send_bytes;
    public Number received_pkts;
    public Number send_pkts;
    public Number error_pkts;

    public this()
    {
        received_bytes = new Count();
        send_bytes = new Count();
        received_pkts = new Count();
        send_pkts = new Count();
        error_pkts = new Count();
    }

    public ~this()
    {
        delete received_bytes;
        delete send_bytes;
        delete received_pkts;
        delete send_pkts;
        delete error_pkts;
    }    

    public void add(Stats payload)
    {
        switch (payload)
        {
            case .ReceivedBytes(let v): received_bytes.add(v); break;
            case .ReceivedPkts(let v): received_pkts.add(v); break;
            case .SendBytes(let v): send_bytes.add(v); break;
            case .SendPkts(let v): send_pkts.add(v); break;
            case .ErrorPkts(let v): error_pkts.add(v); break;
        }
    }
}

/// worker cluster statistics
class Statistics
{
    public Dictionary<BeefSturn.Turn.SessionAddr, Counts> statsDict;
    public RWLock statsDictLock;

    public this()
    {
        statsDict = new Dictionary<BeefSturn.Turn.SessionAddr, Counts>(1024);
        statsDictLock = new RWLock();
    }

    public this(Statistics copyStats) : this()
    {
        for (let csdict in copyStats.statsDict)
        {
            statsDict.Add(csdict.key, csdict.value);
        }    
    }

    public ~this()
    {
        DeleteDictionaryAndValues!(statsDict);
        delete statsDictLock;
    }

    /// get signal sender
    ///
    /// The signal sender can notify the statisticsing instance to update
    /// internal statistics.
    public StatisticsReporter get_reporter(Transport transport)
    {
        StatisticsReporter statsRep = StatisticsReporter(statsDict.GetEnumerator(), transport);
        return statsRep;
    }

    /// Add an address to the watch list
    public void register(BeefSturn.Turn.SessionAddr addr)
    {
        using (statsDictLock.Write())
        {
            statsDict.Add(
                addr,
                new Counts()
            );
        }
    }

    /// Remove an address from the watch list
    public void unregister(BeefSturn.Turn.SessionAddr addr)
    {
        using (statsDictLock.Write())
        {
            statsDict.Remove(addr);
        }
    }

    /// Obtain a list of statistics from statisticsing
    public Counts get(BeefSturn.Turn.SessionAddr addr)
    {
        using(statsDictLock.Read())
        {
            return statsDict.GetValue(addr);
        }
    }
}

/// statistics reporter
///
/// It is held by each worker, and status information can be sent to the
/// statisticsing instance through this instance to update the internal
/// statistical information of the statistics.
struct StatisticsReporter : IDisposable
{
    public Dictionary<BeefSturn.Turn.SessionAddr, Counts> table;
    public Transport transport;

    public RWLock tableLock;

    public this()
    {
        table = new Dictionary<BeefSturn.Turn.SessionAddr, Counts>();
        transport = Transport.UDP;
        tableLock = new RWLock();
    }

    public this(Dictionary<BeefSturn.Turn.SessionAddr, Counts>.Enumerator table, Transport transport)
    {
        this.table = new Dictionary<BeefSturn.Turn.SessionAddr, Counts>(table);
        this.transport = transport;
        tableLock = new RWLock();
    }

    public void Dispose()
    {
        delete table;
        delete tableLock;
    }

    public void send(BeefSturn.Turn.SessionAddr addr, Span<Stats> reports)
    {
        using (tableLock.Write())
        {
            Counts counts = table.GetValue(addr);
            for (let item in reports)
            {
                counts.add(item);
            }

            table[addr] = counts;
        }
    }
}
