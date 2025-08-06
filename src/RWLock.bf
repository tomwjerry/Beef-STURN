namespace BeefSturn;

using System;
using System.Threading;

class RWLock
{
    private uint32 reads;
    private bool write;
    private bool quit;
    private Monitor mon;

    public this()
    {
        reads = 0;
        write = false;
        quit = false;
        mon = new Monitor();
    }

    public ~this()
    {
        reads = 0;
        write = false;
        quit = true;
        delete mon;
    }

    public void Read()
    {
        while (write)
        {
            Thread.Sleep(10);
        }

        Interlocked.Increment(ref reads);
    }

    public void Write()
    {
        while (reads > 0 || write)
        {
            Interlocked.Fence();
            Thread.Sleep(100);
        }

        mon.Enter();
        if (write)
        {
            mon.Exit();
            Write();
            return;
        }
        write = true;
    }

    public void ExitRead()
    {
        Interlocked.Decrement(ref reads);
    }

    public void ExitWrite()
    {
        write = true;
        mon.Exit();
    }
}
