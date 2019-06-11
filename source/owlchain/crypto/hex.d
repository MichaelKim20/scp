module owlchain.crypto.hex;

import std.exception:enforce;
import wrapper.sodium.utils:sodium_hex2bin,sodium_bin2hex;
import std.stdio:writefln;
import std.string : representation;
import std.exception : enforce, assumeWontThrow, assumeUnique;

import owlchain.xdr;

string _sodium_bin2hex(in ubyte[] bin) pure nothrow @trusted
{
//  enforce(bin !is null, "bin is null"); // not necessary
  static import deimos.sodium.utils;
  char[] hex = new char[2*bin.length+1];
// hex[0..$-1] strips terminating null character; assumeUnique not strictly required, as compiler can infer uniqueness for a pure function
  return (assumeWontThrow(sodium_bin2hex(hex.ptr, hex.length, bin.ptr, bin.length))? hex[0..$-1] : cast(char[])null);
}

int _sodium_hex2bin(scope ubyte[] bin, in string hex, in string ignore, out size_t bin_len, out string hex_end) pure nothrow @trusted
{
  import std.string : toStringz, fromStringz;
  static import deimos.sodium.utils;
  const(char)*  hex_end_ptr;
  /* in the next function call:
     prefering  toStringz(ignore) i.e. possibly a copy over ignore.ptr is conservative: AFAIK it's not reliable to have a '\0' in memory behind a D string  */
  int rv = assumeWontThrow(sodium_hex2bin(bin.ptr, bin.length, hex.ptr, hex.length, toStringz(ignore), &bin_len, &hex_end_ptr));
  hex_end = fromStringz(hex_end_ptr).idup;
  return rv;
}


string binToHex(in ubyte[] bin)
{
    return _sodium_bin2hex(bin);
}
alias toHex = binToHex; 

string hexAbbrev(in ubyte[] bin)
{
    size_t sz = bin.length;
    if (sz > 3)
    {
        sz = 3;
    }
    return binToHex(bin[0 .. sz]);
}

string hexAbbrev(ref Hash h)
{
    return hexAbbrev(h.hash);
}

ubyte[] hexToBin(in string hex,string ignore=null)
{
    ubyte[] bin = new ubyte[hex.length];
    size_t  bin_len;
    string  hex_end;
    enforce(_sodium_hex2bin(bin, hex, ignore, bin_len, hex_end) == 0);
    bin = bin[0 .. bin_len];
    return bin;
}
alias toBin = hexToBin;

ubyte[32] hexToBin256(in ubyte[64] hex){
    auto bin = hexToBin(cast(string)hex);
    enforce(bin.length == 32);
    return bin[0 .. 32];
}

@("hex")
@system
unittest{

    ubyte[][] binData = [
        cast(ubyte[]) x"12",
        cast(ubyte[]) x"12 34",
        cast(ubyte[]) x"12 34 56",
        cast(ubyte[]) x"12 34 56 78",
        cast(ubyte[]) x"12 34 56 78 90",
        cast(ubyte[]) x"12 34 56 78 90 ab",
        cast(ubyte[]) x"12 34 56 78 90 ab cd",
        cast(ubyte[]) x"12 34 56 78 90 AB CD EF"
    ];

    foreach(ubyte[] bin; binData){
        auto b1 = bin.toHex.toBin; // auto b1 = toBin(toHex(bin));
        assert(bin == b1);
    }

    assert(toHex(cast(ubyte[])x"12 34") == "1234");
    assert(toBin("12:34:56", ":") == x"12 34 56");

    auto b256 = hexToBin256(cast(ubyte[64])"1234567890123456789012345678901234567890123456789012345678901234");
    writefln("b256 %s", b256);

    writefln("hexToBin(binToHex((bin)) is done");
}
