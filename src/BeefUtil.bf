namespace BeefSturn;
using System;
using System.Collections;
using Beef_Net;

static
{
    public static SocketAddress ParseSocketAddress(StringView value)
    {
        var addr = value.Split(':');
        StringView ip = addr.GetNext();
        uint16 port = UInt16.Parse(addr.GetNext());
        sa_family_t family = AF_INET;
        // IPv6
        if (addr.HasMore)
        {
            family = AF_INET6;
            ip = value.Substring(0, value.LastIndexOf(':'));
            port = UInt16.Parse(value.Substring(value.LastIndexOf(':') + 1));
        }

        SocketAddress sa = SocketAddress();
        Common.FillAddressInfo(ref sa, family, ip, port);
        return sa;
    }
}

interface STError
{
}

class ByteList : List<uint8>
{
    public void AddU16(uint16 val)
    {
        Add((uint8)(val >> 8));
        Add((uint8)(val & 0xFF));
    }

    public void AddU32(uint32 val)
    {
        Add((uint8)(val >> 24));
        Add((uint8)(val >> 16));
        Add((uint8)(val >> 8));
        Add((uint8)(val & 0xFF));
    }

    public void AddU64(uint64 val)
    {
        Add((uint8)(val >> 56));
        Add((uint8)(val >> 48));
        Add((uint8)(val >> 40));
        Add((uint8)(val >> 32));
        Add((uint8)(val >> 24));
        Add((uint8)(val >> 16));
        Add((uint8)(val >> 8));
        Add((uint8)(val & 0xFF));
    }

    public static uint16 ReadU16(Span<uint8> bytes, int offset)
    {
        return ((uint16)bytes[offset] << 8 | bytes[offset + 1]);
    }

    public static uint32 ReadU32(Span<uint8> bytes, int offset)
    {
        return ((uint32)bytes[offset] << 24 | (uint32)bytes[offset + 1] << 16 |
            (uint32)bytes[offset + 2] << 8 | bytes[offset + 3]);
    }

    public static uint64 ReadU64(Span<uint8> bytes, int offset)
    {
        return ((uint64)bytes[offset] << 56 |
            (uint64)bytes[offset + 1] << 48 |
            (uint64)bytes[offset + 2] << 40 |
            (uint64)bytes[offset + 3] << 32 |
            (uint64)bytes[offset + 4] << 24 |
            (uint64)bytes[offset + 5] << 16 |
            (uint64)bytes[offset + 6] << 8 |
            bytes[offset + 7]);
    }

    public static uint16 ReadU16(Span<uint8> bytes)
    {
        return ReadU16(bytes, 0);
    }

    public static uint32 ReadU32(Span<uint8> bytes)
    {
        return ReadU32(bytes, 0);
    }

    public static uint64 ReadU64(Span<uint8> bytes)
    {
        return ReadU64(bytes, 0);
    }
}

class Log
{
    public static void Info(StringView msg, params Object[] msgParams)
    {
        Console.WriteLine(msg, params msgParams);
    }

    public static void Error(StringView msg, params Object[] msgParams)
    {
        Console.WriteLine(msg, params msgParams);
    }
}
