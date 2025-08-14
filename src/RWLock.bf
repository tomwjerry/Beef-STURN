namespace BeefSturn;

using System;
using System.Threading;

class RWLock
{
    public struct LockIns : IDisposable
    {
        private RWLock lck;
        private bool isWrite;

        public this(RWLock mylck, bool mywrite)
        {
            lck = mylck;
            isWrite = mywrite;
        }

        public void Dispose()
        {
            if (isWrite)
            {
                lck.ExitWrite();
            }
            else
            {
                lck.ExitRead();
            }
        }
    }

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

    public LockIns Read()
    {
        LockIns curIns = LockIns(this, false);
        while (write && !quit)
        {
            Thread.Sleep(10);
        }

        Interlocked.Increment(ref reads);
        return curIns;
    }

    public LockIns Write()
    {
        LockIns curIns = LockIns(this, true);
        while (!quit && (reads > 0 || write))
        {
            Interlocked.Fence();
            Thread.Sleep(9);
        }

        mon.Enter();
        if (!Interlocked.CompareExchange(ref write, false, true) && !quit)
        {
            mon.Exit();
            return Write();
        }
        
        return curIns;
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
