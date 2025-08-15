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
    private uint32 shutdowns;

    public this()
    {
        reads = 0;
        write = false;
        quit = false;
        mon = new Monitor();
    }

    public ~this()
    {
        quit = true;
        reads = 0;
        write = false;
        
        while (shutdowns > 0) {}
        
        delete mon;
    }

    public LockIns Read()
    {
        Interlocked.Increment(ref shutdowns);
        LockIns curIns = LockIns(this, false);
        while (write && !quit)
        {
            Thread.Sleep(10);
        }

        Interlocked.Decrement(ref shutdowns);

        if (quit)
        {
            return curIns;
        }

        Interlocked.Increment(ref reads);
        return curIns;
    }

    public LockIns Write()
    {
        Interlocked.Increment(ref shutdowns);

        LockIns curIns = LockIns(this, true);

        while (!quit && (reads > 0 || write))
        {
            Interlocked.Fence();
            Thread.Sleep(9);
        }

        Interlocked.Decrement(ref shutdowns);

        if (quit)
        {
            return curIns;
        }
        
        if (Interlocked.CompareExchange(ref write, false, true) === true && !quit)
        {
            return Write();
        }

        mon.Enter();
        
        return curIns;
    }

    public void ExitRead()
    {
        Interlocked.Decrement(ref reads);
    }

    public void ExitWrite()
    {
        write = false;
        mon.Exit();
    }
}
