module owlchain.crypto.sha;

import wrapper.sodium;

import owlchain.xdr;

// Plain SHA256
uint256 sha256(in ubyte[] bin)
{
    uint256 res;
    if (crypto_hash_sha256(res, bin) != 0)
    {
        throw new Exception("error from crypto_hash_sha256");
    }
    return res;
}

// SHA256 in incremental mode, for large inputs.
class SHA256
{
private:
    static SHA256 mInstance;
    crypto_hash_sha256_state mState;
    bool mFinished;
public:
    static SHA256 create()
    {
        if (mInstance is null) {
            mInstance = new SHA256();
        }

        return mInstance;
    }
    this()
    {
        mFinished = false;
        reset();
    }

    ~this()
    {

    };

    void reset() 
    {
        if (crypto_hash_sha256_init(mState) != 0)
        {
            throw new Exception("error from crypto_hash_sha256_init");
        }
        mFinished = false;
        
    };

    void add(in ubyte[] bin)
    {
        if (mFinished)
        {
            throw new Exception("adding bytes to finished SHA256");
        }
        if (crypto_hash_sha256_update(mState, bin) != 0)
        {
            throw new Exception("error from crypto_hash_sha256_update");
        }
    }

    uint256 finish()
    {
        uint256 res;
        assert(res.length == crypto_hash_sha256_BYTES);

        if (mFinished)
        {
            throw new Exception("finishing already-finished SHA256");
        }
        if (crypto_hash_sha256_final(mState, res) != 0)
        {
            throw new Exception("error from crypto_hash_sha256_final");
        }
        return res;
    }
};

// HMAC-SHA256 (keyed)
HmacSha256Mac hmacSha256(out HmacSha256Key key, in ubyte[] bin)
{
    HmacSha256Mac res;
    if (crypto_auth_hmacsha256(res.mac, bin, key.key) != 0)
    {
        throw new Exception("error from crypto_auto_hmacsha256");
    }
    return res;
}

// Use this rather than HMAC-output ==, to avoid timing leaks.
bool hmacSha256Verify(in HmacSha256Mac hmac, in HmacSha256Key key, in ubyte[] bin)
{
    return 0 == crypto_auth_hmacsha256_verify(hmac.mac, bin, key.key);
}

// Unsalted HKDF-extract(bytes) == HMAC(<zero>,bytes)
HmacSha256Key hkdfExtract(ref ubyte[] bin)
{
    HmacSha256Key zerosalt;
    auto mac = hmacSha256(zerosalt, bin);
    HmacSha256Key key;
    key.key = mac.mac;
    return key;
}

// Single-step HKDF-expand(key,bytes) == HMAC(key,bytes|0x1)
HmacSha256Key hkdfExpand(ref HmacSha256Key key, ref ubyte[] bin)
{
    ubyte[] bytes;
    bytes = bin.dup;
    bytes ~= 1;
    auto mac = hmacSha256(key, bytes);
    HmacSha256Key res;
    res.key = mac.mac.dup;
    return res;
}
