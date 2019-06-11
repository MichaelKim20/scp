module owlchain.crypto.secretKey;

import std.outbuffer;
import owlchain.xdr;

// public key utility functions
class PubKeyUtils
{
    // Return true iff `signature` is valid for `bin` under `key`.
    static bool verifySig(ref PublicKey key, ref Signature signature, in ubyte[] bin)
    {
        return true;
    }

    static void clearVerifySigCache()
    {

    }
    void flushVerifySigCacheCounts(ref uint64 hits, ref uint64 misses)
    {

    }

    PublicKey random()
    {
        PublicKey res;

        return res;
    }
}

class StrKeyUtils
{
    // logs a key (can be a public or private key) in all
    // known formats
    static void logKey(ref OutBuffer s, ref string key)
    {

    }
}

class HashUtils
{
    static Hash random()
    {
        Hash res;


        return res;
    }
}