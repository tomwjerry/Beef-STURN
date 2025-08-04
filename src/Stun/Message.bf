namespace BeefSturn.Stun;

using System;
using System.Collections;
using System.Diagnostics;

static
{
    const uint8[10] ZERO_BUF = uint8[10](0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    const uint8[4] COOKIE = uint8[4](0x21, 0x12, 0xa4, 0x42);
}

/// (username, password, realm)
struct Digest
{
    public uint8[16] bytes;
    public this(uint8[16] bytes)
    {
        this.bytes = bytes;
    }
}

class MessageEncoder
{
    public Span<uint8> token;
    public List<uint8> bytes;

    public this(Span<uint8> ttoken, Span<uint8> tbytes)
    {
        bytes = new List<uint8>(tbytes);
        token = ttoken;
    }    

    public this(Method.StunMethod method, uint8[12] ttoken, List<uint8> tbytes)
    {
        tbytes.Clear();

        uint16 methodNum = method.Into();
        tbytes.Add((uint8)(methodNum >> 8));
        tbytes.Add((uint8)(methodNum & 0xFF));
        tbytes.Add(0);
        tbytes.Add(0);
        tbytes.AddRange(COOKIE);
        tbytes.AddRange(ttoken);

        bytes = new List<uint8>(tbytes);
        token = ttoken;
    }

    public ~this()
    {
        delete bytes;
    }

    /// rely on old message to create new message.
    public void extend(Method.StunMethod method, MessageRef reader, List<uint8> nbytes, MessageEncoder newMsg)
    {
        Span<uint8> ttoken = reader.token();

        nbytes.Clear();
        uint16 methodNum = method.Into();
        nbytes.Add((uint8)(methodNum >> 8));
        nbytes.Add((uint8)(methodNum & 0xFF));
        nbytes.Add(0);
        nbytes.Add(0);
        nbytes.AddRange(COOKIE);
        nbytes.AddRange(ttoken);

        newMsg.bytes.Clear();
        nbytes.CopyTo(newMsg.bytes);
        newMsg.token = ttoken;
    }

    /// append attribute.
    ///
    /// append attribute to message attribute list.
    public void appendAttr<T>(T theval) where T : STAttribute
    {
        uint16 pootVal = BitConverter.Convert<T, uint16>(theval);
        bytes.Add((uint8)(pootVal >> 8));
        bytes.Add((uint8)(pootVal & 0xFF));

        // record the current position,
        // and then advance the internal cursor 2 bytes,
        // here is to reserve the position.
        int os = bytes.Count;
        bytes.GrowUninitialized(2);
        theval.encode(bytes, token);

        // compute write index,
        // back to source index write size.
        int size = bytes.Count - os - 2;
        bytes[os] = (uint8)(size >> 8);
        bytes[os + 1] = (uint8)(size & 0xFF);

        // if you need to padding,
        // padding in the zero bytes.
        int psize = (int)pad_size((uint64)size);
        if (psize > 0)
        {
            for (int i = 0; i < psize; i++)
            {
                bytes.Add(0);
            }
        }
    }

    /// try decoder bytes as message.
    public Result<void, StunError> flush(Digest? digest)
    {
        // write attribute list size.
        set_len((uint64)bytes.Count - 20);

        // if need message integrity?
        if (digest.TryGetValue(var a))
        {
            integrity(a);
        }

        return .Ok;
    }

    /// append MessageIntegrity attribute.
    ///
    /// add the `MessageIntegrity` attribute to the stun message
    /// and serialize the message into a buffer.
    ///
    private Result<void, StunError> integrity(Digest digest)
    {
        Debug.Assert(bytes.Count >= 20);
        int len = bytes.Count;

        // compute new size,
        // new size include the MessageIntegrity attribute size.
        set_len((uint64)len + 4);

        // write MessageIntegrity attribute.
        Span<uint8>[] bytespan = scope Span<uint8>[1](bytes.GetRange(0));
        Span<Span<uint8>> spanospan = Span<Span<uint8>>(bytespan, 0);
        let hmac_output = hmac_sha1(digest.bytes, spanospan);
        if (hmac_output case .Ok(let hmacbytes))
        {
            uint16 msgIntegrity = AttrKind.MessageIntegrity.Underlying;
            bytes.Add((uint8)(msgIntegrity >> 8));
            bytes.Add((uint8)(msgIntegrity & 0xFF));
            bytes.Add(0);
            bytes.Add(20);
            bytes.AddRange(hmacbytes);
        }
        else
        {
            return .Err(.SummaryFailed);
        }

        // compute new size,
        // new size include the Fingerprint attribute size.
        set_len((uint64)len + 4 + 8);

        // CRC Fingerprint
        uint32 fingerprint = fingerprint(bytes);
        bytes.Add((uint8)(AttrKind.Fingerprint.Underlying >> 8));
        bytes.Add((uint8)(AttrKind.Fingerprint.Underlying & 0xFF));
        bytes.Add(0);
        bytes.Add(4);
        bytes.Add((uint8)(fingerprint >> 24));
        bytes.Add((uint8)(fingerprint >> 16));
        bytes.Add((uint8)(fingerprint >> 8));
        bytes.Add((uint8)(fingerprint & 0xFF));

        return .Ok;
    }

    // set stun message header size.
    private void set_len(uint64 len)
    {
        bytes[2] = (uint8)(len >> 8);
        bytes[3] = (uint8)(len & 0xFF);
    }
}

class MessageDecoder
{
    public static Result<MessageRef, StunError> decode(Span<uint8> bytes, Attributes attributes)
    {
        if (bytes.Length < 20)
        {
            return .Err(StunError.InvalidInput);
        }

        int count_size = bytes.Length;
        bool find_integrity = false;
        int payload_size = 0;

        // message type
        // message size
        // check fixed magic cookie
        // check if the message size is overflow
        Method.StunMethod method = Method.StunMethod.TryFrom((uint16)bytes[1] << 8 | bytes[0]);
        uint16 size = ((uint16)bytes[3] << 8 | bytes[2]) + 20;
        if (bytes[4] != COOKIE[0] || bytes[5] != COOKIE[1] ||
            bytes[6] != COOKIE[2] || bytes[7] != COOKIE[3])
        {
            return .Err(StunError.NotFoundCookie);
        }

        if (count_size < size)
        {
            return .Err(StunError.InvalidInput);
        }

        int offset = 20;
        while (count_size - offset > 4)
        {
            // if the buf length is not long enough to continue,
            // jump out of the loop.

            // get attribute type
            uint16 key = (uint16)bytes[offset + 1] << 8 | bytes[offset];

            // whether the MessageIntegrity attribute has been found,
            // if found, record the current offset position.
            if (!find_integrity)
            {
                payload_size = offset;
            }

            // check whether the current attribute is MessageIntegrity,
            // if it is, mark this attribute has been found.
            if (key == (uint16)AttrKind.MessageIntegrity.Underlying)
            {
                find_integrity = true;
            }

            // get attribute size
            uint16 bsize = (uint16)bytes[offset + 3] << 8 | bytes[offset + 2];

            // check if the attribute length has overflowed.
            offset += 4;
            if (count_size - offset < bsize)
            {
                break;
            }

            // body range.
            uint64 rangeMin = (uint64)offset;

            // if there are padding bytes,
            // skip padding size.
            if (bsize > 0)
            {
                offset += bsize;
                offset += (int)pad_size(bsize);
            }

            // skip the attributes that are not supported.
            AttrKind attrkind;
            if (!(AttrKind.TryFrom(key) case .Ok(out attrkind)))
            {
                continue;
            }

            // get attribute body
            // insert attribute to c=attributes list.
            attributes.aAppend(attrkind, uint64[2](rangeMin, bsize));
        }

        return .Ok(MessageRef {
            size = (uint16)payload_size,
            attributes = attributes,
            method = method,
            bytes = bytes
        });
    }

    public static Result<uint64, StunError> message_size(Span<uint8> buf)
    {
        if (buf[0] >> 6 != 0 || buf.Length < 20)
        {
            return .Err(StunError.InvalidInput);
        }

        return .Ok(((uint64)buf[3] << 8 | buf[2]) + 20);
    }
}

struct MessageRef
{
    /// message method.
    public Method.StunMethod method;
    /// message source bytes.
    public Span<uint8> bytes;
    /// message payload size.
    public uint16 size;
    // message attribute list.
    public Attributes attributes;

    /// message method.
    public Method.StunMethod method()
    {
        return method;
    }

    /// message transaction id.
    public Span<uint8> token()
    {
        return bytes.Slice(8, 12);
    }

    private Result<STAttribute, STError> getAttrHelper(AttrKind getWhat, uint64[2] range)
    {
        switch (getWhat)
        {
        case .UserName:
            return UserName.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .Data:
            return Data.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .MappedAddress:
            return MappedAddress.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .MessageIntegrity:
            return MessageIntegrity.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .ErrorCode:
            return ErrorCode.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .ChannelNumber:
            return ChannelNumber.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .Lifetime:
            return Lifetime.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .XorPeerAddress:
            return XorPeerAddress.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .Realm:
            return Realm.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .Nonce:
            return Nonce.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .XorRelayedAddress:
            return Nonce.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .RequestedAddressFamily:
            return RequestedAddressFamily.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .EvenPort:
            return EvenPort.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .RequestedTransport:
            return RequestedTransport.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .DontFragment:
            return DontFragment.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .AccessToken:
            return AccessToken.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .XorMappedAddress:
            return XorMappedAddress.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .ReservationToken:
            return ReservationToken.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .Priority:
            return Priority.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .UseCandidate:
            return UseCandidate.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .AdditionalAddressFamily:
            return AdditionalAddressFamily.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .Software:
            return Software.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .Fingerprint:
            return Fingerprint.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .IceControlled:
            return IceControlled.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .IceControlling:
            return IceControlling.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        case .ResponseOrigin:
            return ResponseOrigin.decode(bytes.Slice((int)range[0], (int)range[1]), this.token());

        default:
            return .Err(StunError.InvalidInput);
        }
    }

    /// get attribute.
    ///
    /// get attribute from message attribute list.
    public Result<STAttribute, STError> getAttr(AttrKind getWhat)
    {
        return getAttrHelper(getWhat, attributes.get(getWhat));
    }

    /// Gets all the values of an attribute from a list.
    ///
    /// Normally a stun message can have multiple attributes with the same name,
    /// and this function will all the values of the current attribute.
    public Span<STAttribute> get_all(AttrKind getWhat)
    {
        Span<uint64[2]>.Enumerator attrRanges = attributes.get_all(getWhat);
        List<STAttribute> collectionList = scope List<STAttribute>();

        for (let r in attrRanges)
        {
            if (getAttrHelper(getWhat, r) case .Ok(let outAttr))
            {
                collectionList.Add(outAttr);
            }
        }

        return collectionList;
    }

    /// check MessageRefIntegrity attribute.
    ///
    /// return whether the `MessageRefIntegrity` attribute
    /// contained in the message can pass the check.
    public Result<void, StunError> integrity(Digest digest)
    {
        if (bytes.IsEmpty || size < 20)
        {
            return .Err(StunError.InvalidInput);
        }

        // unwrap MessageIntegrity attribute,
        // an error occurs if not found.
        MessageIntegrity integrity;

        if (getAttr(.MessageIntegrity) case .Ok(let lintegrity))
        {
            integrity = (MessageIntegrity)lintegrity;
        }
        else
        {
            return .Err(.NotFoundIntegrity);
        }

        // create multiple submit.
        uint8[3] size_buf = uint8[3]();
        size_buf[0] = (uint8)((uint32)(size + 4) >> 16);
        size_buf[1] = (uint8)((size + 4) >> 8);
        size_buf[2] = (uint8)((size + 4) & 0xFF);
        uint8[] body = scope uint8[size + 5];
        body[0] = bytes[0];
        body[1] = bytes[1];
        body[2] = size_buf[0];
        body[3] = size_buf[1];
        body[4] = size_buf[2];
        for (int i = 4; i < size; i++)
        {
            body[i + 5] = bytes[i];
        }

        // digest the message buffer.
        let hmac_output = hmac_sha1((Span<uint8>)digest.bytes, Span<Span<uint8>>(scope Span<uint8>[]((Span<uint8>)body)));
        if (hmac_output case .Ok(let hmac_buf))
        {
            // Compare local and original attribute.
            if (integrity.byteVal != hmac_buf)
            {
                return .Err(.IntegrityFailed);
            }
    
            return .Ok;
        }

        return .Err(.NotFoundIntegrity);
    }
}
