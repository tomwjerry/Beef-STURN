namespace BeefSturn.Stun;

using System;
using System.Security.Cryptography;
using BeefCrypto;

/// compute padding size.
///
/// RFC5766 stipulates that the attribute
/// content is a multiple of 4.
static
{
    public static uint64 pad_size(uint64 size)
    {
        uint64 range = size % 4;
        if (size == 0 || range == 0)
        {
            return 0;
        }

        return 4 - range;
    }

    /// create long term credential.
    public static uint8[16] long_term_credential_digest(StringView username, StringView password, StringView realm)
    {
        String joined = scope String(username);
        joined.Append(":");
        joined.Append(realm);
        joined.Append(":");
        joined.Append(password);
        MD5Hash hasher = MD5.Hash(.((.)joined, joined.Length));
        return hasher.mHash;
    }

    /// HMAC SHA1 digest.
    public static Result<Span<uint8>, StunError> hmac_sha1(Span<uint8> key, Span<Span<uint8>> source)
    {
        HMACSHA1 hmac = scope HMACSHA1(key);

        for (let buf in source)
        {
            uint8[] inbuf = scope uint8[key.Length];
            key.CopyTo(inbuf);
            uint8[] opbuf = scope uint8[key.Length];
            hmac.TransformBlock(inbuf, 0, key.Length, opbuf, 0);
        }

        if (hmac.TransformFinalBlock(scope uint8[0], 0, 0) case .Ok(let res))
        {
            return .Ok(res);
        }

        return .Err(.SummaryFailed);
    }
    
    /// CRC32 Fingerprint.
    public static uint32 fingerprint(Span<uint8> bytes)
    {
        return CRC.Hash(bytes) ^ 0x5354554e;
    }
}
