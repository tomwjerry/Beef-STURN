namespace BeefSturn.Stun;

using System;
using System.Collections;

/// The ChannelData Message
///
/// The ChannelData message is used to carry application data between the
/// client and the server.  
/// It has the following format:
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Channel Number        |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                       Application Data                        /
/// /                                                               /
/// |                                                               |
/// |                               +-------------------------------+
/// |                               |
/// +-------------------------------+
///
///                               Figure 5
/// ```
///
/// The Channel Number field specifies the number of the channel on which
/// the data is traveling, and thus, the address of the peer that is
/// sending or is to receive the data.
///
/// The Length field specifies the length in bytes of the application
/// data field (i.e., it does not include the size of the ChannelData
/// header).  Note that 0 is a valid length.
///
/// The Application Data field carries the data the client is trying to
/// send to the peer, or that the peer is sending to the client.
struct ChannelData
{
    /// channnel data bytes.
    public Span<uint8> bytes;
    /// channel number.
    public uint16 number;

    public Result<uint64, StunError> message_size(Span<uint8> bytes, bool is_tcp)
    {
        if (bytes.Length < 4)
        {
            return .Err(StunError.InvalidInput);
        }

        if (!(uint8[2](1, 2)).Contains(bytes[0] >> 6))
        {
            return .Err(StunError.InvalidInput);
        }

        uint64 size = BitConverter.Convert<uint8[2], uint16>(uint8[2](bytes[2], bytes[3])) + 4;
        if (is_tcp && (size % 4) > 0)
        {
            size += 4 - (size % 4);
        }

        return .Ok(size);
    }

    public void encode(List<uint8> obytes)
    {
        obytes.Clear();
        obytes.Add((uint8)(number >> 8));
        obytes.Add((uint8)(number & 0xFF));
        obytes.Add((uint8)(bytes.Length >> 8));
        obytes.Add((uint8)(bytes.Length & 0xFF));
        obytes.AddRange(bytes);
    }

    public Result<ChannelData, StunError> TryFrom(Span<uint8> bytes)
    {
        if (bytes.Length < 4)
        {
            return .Err(StunError.InvalidInput);
        }

        if (!(uint8[2](1, 2)).Contains(bytes[0] >> 6))
        {
            return .Err(StunError.InvalidInput);
        }

        uint16 number = BitConverter.Convert<uint8[2], uint16>(uint8[2](bytes[0], bytes[1]));
        uint16 length = BitConverter.Convert<uint8[2], uint16>(uint8[2](bytes[2], bytes[3]));

        return .Ok(ChannelData
        {
            number = number,
            bytes = bytes.Slice(4, length)
        });
    }
}
