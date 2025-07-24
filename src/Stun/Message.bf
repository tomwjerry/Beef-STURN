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

    public this(Method.StunMethod method, uint8[12] ttoken, Span<uint8> tbytes)
    {
        List<uint8> tmpBytes = scope List<uint8>();

        uint16 methodNum = method.Into();
        tmpBytes.Add((uint8)(methodNum >> 8));
        tmpBytes.Add((uint8)(methodNum & 0xFF));
        tmpBytes.Add(0);
        tmpBytes.Add(0);
        tmpBytes.AddRange(COOKIE);
        tmpBytes.AddRange(ttoken);

        this(tmpBytes, tbytes);
    }

    public void Dispose()
    {
        delete bytes;
    }

    /// rely on old message to create new message.
    public void extend(Method.StunMethod method, MessageRef reader, Span<uint8> nbytes) mut
    {
        Span<uint8> ttoken = reader.token();

        bytes.Clear();
        uint16 methodNum = method.Into();
        bytes.Add((uint8)(methodNum >> 8));
        bytes.Add((uint8)(methodNum & 0xFF));
        bytes.Add(0);
        bytes.Add(0);
        bytes.AddRange(COOKIE);
        bytes.AddRange(ttoken);

        token = ttoken;
    }

    /// append attribute.
    ///
    /// append attribute to message attribute list.
    public void appendAttr<T>(T theval) where T : Encodable
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
        let psize = pad_size(size);
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
        set_len(bytes.Count - 20);

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
    Result<void, StunError> integrity(Digest digest)
    {
        Debug.Assert(bytes.Count >= 20);
        int len = bytes.Count;

        // compute new size,
        // new size include the MessageIntegrity attribute size.
        set_len(len + 4);

        // write MessageIntegrity attribute.
        let hmac_output = hmac_sha1(digest, bytes).into_bytes();
        uint16 msgIntegrity = AttrKind.MessageIntegrity.into();
        self.bytes.put_u16(AttrKind::MessageIntegrity as u16);
        self.bytes.put_u16(20);
        self.bytes.put(hmac_output.as_slice());

        // compute new size,
        // new size include the Fingerprint attribute size.
        self.set_len(len + 4 + 8);

        // CRC Fingerprint
        let fingerprint = util::fingerprint(self.bytes);
        self.bytes.put_u16(AttrKind::Fingerprint as u16);
        self.bytes.put_u16(4);
        self.bytes.put_u32(fingerprint);

        Ok(())
    }

    // set stun message header size.
    fn set_len(&mut self, len: usize) {
        self.bytes[2..4].copy_from_slice((len as u16).to_be_bytes().as_slice());
    }
}

pub struct MessageDecoder;

impl MessageDecoder {
    /// # Test
    ///
    /// ```
    /// use std::convert::TryFrom;
    /// use turn_server::stun::attribute::*;
    /// use turn_server::stun::method::*;
    /// use turn_server::stun::*;
    ///
    /// let buffer: [u8; 20] = [
    ///     0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x72, 0x6d, 0x49, 0x42,
    ///     0x72, 0x52, 0x64, 0x48, 0x57, 0x62, 0x4b, 0x2b,
    /// ];
    ///
    /// let mut attributes = Attributes::default();
    /// let message = MessageDecoder::decode(&buffer[..], &mut attributes).unwrap();
    /// assert_eq!(
    ///     message.method(),
    ///     StunMethod::Binding(StunMethodKind::Request)
    /// );
    /// assert!(message.get::<UserName>().is_none());
    /// ```
    pub fn decode<'a>(bytes: &'a [u8], attributes: &'a mut Attributes) -> Result<MessageRef<'a>, StunError> {
        if bytes.len() < 20 {
            return Err(StunError::InvalidInput);
        }

        let count_size = bytes.len();
        let mut find_integrity = false;
        let mut payload_size = 0;

        // message type
        // message size
        // check fixed magic cookie
        // check if the message size is overflow
        let method = StunMethod::try_from(u16::from_be_bytes(bytes[..2].try_into()?))?;
        let size = u16::from_be_bytes(bytes[2..4].try_into()?) as usize + 20;
        if bytes[4..8] != COOKIE[..] {
            return Err(StunError::NotFoundCookie);
        }

        if count_size < size {
            return Err(StunError::InvalidInput);
        }

        let mut offset = 20;
        loop {
            // if the buf length is not long enough to continue,
            // jump out of the loop.
            if count_size - offset < 4 {
                break;
            }

            // get attribute type
            let key = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);

            // whether the MessageIntegrity attribute has been found,
            // if found, record the current offset position.
            if !find_integrity {
                payload_size = offset as u16;
            }

            // check whether the current attribute is MessageIntegrity,
            // if it is, mark this attribute has been found.
            if key == AttrKind::MessageIntegrity as u16 {
                find_integrity = true;
            }

            // get attribute size
            let size = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;

            // check if the attribute length has overflowed.
            offset += 4;
            if count_size - offset < size {
                break;
            }

            // body range.
            let range = offset..(offset + size);

            // if there are padding bytes,
            // skip padding size.
            if size > 0 {
                offset += size;
                offset += util::pad_size(size);
            }

            // skip the attributes that are not supported.
            let attrkind = match AttrKind::try_from(key) {
                Err(_) => continue,
                Ok(a) => a,
            };

            // get attribute body
            // insert attribute to attributes list.
            attributes.append(attrkind, range);
        }

        Ok(MessageRef {
            size: payload_size,
            attributes,
            method,
            bytes,
        })
    }

    /// # Test
    ///
    /// ```
    /// use turn_server::stun::*;
    ///
    /// let buffer: [u8; 20] = [
    ///     0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x72, 0x6d, 0x49, 0x42,
    ///     0x72, 0x52, 0x64, 0x48, 0x57, 0x62, 0x4b, 0x2b,
    /// ];
    ///
    /// let size = MessageDecoder::message_size(&buffer[..]).unwrap();
    /// assert_eq!(size, 20);
    /// ```
    pub fn message_size(buf: &[u8]) -> Result<usize, StunError> {
        if buf[0] >> 6 != 0 || buf.len() < 20 {
            return Err(StunError::InvalidInput);
        }

        Ok((u16::from_be_bytes(buf[2..4].try_into()?) + 20) as usize)
    }
}

#[derive(Debug)]
pub struct MessageRef<'a> {
    /// message method.
    method: StunMethod,
    /// message source bytes.
    bytes: &'a [u8],
    /// message payload size.
    size: u16,
    // message attribute list.
    attributes: &'a Attributes,
}

impl<'a> MessageRef<'a> {
    /// message method.
    #[inline]
    pub fn method(&self) -> StunMethod {
        self.method
    }

    /// message transaction id.
    #[inline]
    pub fn token(&self) -> &'a [u8] {
        &self.bytes[8..20]
    }

    /// get attribute.
    ///
    /// get attribute from message attribute list.
    ///
    /// # Test
    ///
    /// ```
    /// use std::convert::TryFrom;
    /// use turn_server::stun::attribute::*;
    /// use turn_server::stun::*;
    ///
    /// let buffer = [
    ///     0x00u8, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x72, 0x6d, 0x49,
    ///     0x42, 0x72, 0x52, 0x64, 0x48, 0x57, 0x62, 0x4b, 0x2b,
    /// ];
    ///
    /// let mut attributes = Attributes::default();
    /// let message = MessageDecoder::decode(&buffer[..], &mut attributes).unwrap();
    /// assert!(message.get::<UserName>().is_none());
    /// ```
    pub fn get<T: Attribute<'a>>(&self) -> Option<T::Item> {
        let range = self.attributes.get(&T::KIND)?;
        T::decode(&self.bytes[range.clone()], self.token()).ok()
    }

    /// Gets all the values of an attribute from a list.
    ///
    /// Normally a stun message can have multiple attributes with the same name,
    /// and this function will all the values of the current attribute.
    ///
    /// # Test
    ///
    /// ```
    /// use std::convert::TryFrom;
    /// use turn_server::stun::attribute::*;
    /// use turn_server::stun::*;
    ///
    /// let buffer = [
    ///     0x00u8, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x72, 0x6d, 0x49,
    ///     0x42, 0x72, 0x52, 0x64, 0x48, 0x57, 0x62, 0x4b, 0x2b,
    /// ];
    ///
    /// let mut attributes = Attributes::default();
    /// let message = MessageDecoder::decode(&buffer[..], &mut attributes).unwrap();
    ///
    /// assert_eq!(message.get_all::<UserName>().next(), None);
    /// ```
    pub fn get_all<T: Attribute<'a>>(&self) -> impl Iterator<Item = T::Item> {
        self.attributes
            .get_all(&T::KIND)
            .map(|it| T::decode(&self.bytes[it.clone()], self.token()))
            .filter(|it| it.is_ok())
            .map(|it| it.unwrap())
    }

    /// check MessageRefIntegrity attribute.
    ///
    /// return whether the `MessageRefIntegrity` attribute
    /// contained in the message can pass the check.
    ///
    /// # Test
    ///
    /// ```
    /// use std::convert::TryFrom;
    /// use turn_server::stun::*;
    ///
    /// let buffer = [
    ///     0x00u8, 0x03, 0x00, 0x50, 0x21, 0x12, 0xa4, 0x42, 0x64, 0x4f, 0x5a,
    ///     0x78, 0x6a, 0x56, 0x33, 0x62, 0x4b, 0x52, 0x33, 0x31, 0x00, 0x19, 0x00,
    ///     0x04, 0x11, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 0x70, 0x61, 0x6e,
    ///     0x64, 0x61, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x09, 0x72, 0x61, 0x73,
    ///     0x70, 0x62, 0x65, 0x72, 0x72, 0x79, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00,
    ///     0x10, 0x31, 0x63, 0x31, 0x33, 0x64, 0x32, 0x62, 0x32, 0x34, 0x35, 0x62,
    ///     0x33, 0x61, 0x37, 0x33, 0x34, 0x00, 0x08, 0x00, 0x14, 0xd6, 0x78, 0x26,
    ///     0x99, 0x0e, 0x15, 0x56, 0x15, 0xe5, 0xf4, 0x24, 0x74, 0xe2, 0x3c, 0x26,
    ///     0xc5, 0xb1, 0x03, 0xb2, 0x6d,
    /// ];
    ///
    /// let mut attributes = Attributes::default();
    /// let message = MessageDecoder::decode(&buffer[..], &mut attributes).unwrap();
    /// let result = message
    ///     .integrity(&util::long_term_credential_digest(
    ///         "panda",
    ///         "panda",
    ///         "raspberry",
    ///     ))
    ///     .is_ok();
    /// assert!(result);
    /// ```
    pub fn integrity(&self, digest: &Digest) -> Result<(), StunError> {
        if self.bytes.is_empty() || self.size < 20 {
            return Err(StunError::InvalidInput);
        }

        // unwrap MessageIntegrity attribute,
        // an error occurs if not found.
        let integrity = self.get::<MessageIntegrity>().ok_or(StunError::NotFoundIntegrity)?;

        // create multiple submit.
        let size_buf = (self.size + 4).to_be_bytes();
        let body = [&self.bytes[0..2], &size_buf, &self.bytes[4..self.size as usize]];

        // digest the message buffer.
        let hmac_output = util::hmac_sha1(digest, &body)?.into_bytes();
        let hmac_buf = hmac_output.as_slice();

        // Compare local and original attribute.
        if integrity != hmac_buf {
            return Err(StunError::IntegrityFailed);
        }

        Ok(())
    }
}
