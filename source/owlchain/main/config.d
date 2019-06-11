module owlchain.main.config;

import owlchain.xdr;
import owlchain.crypto.keyUtils;

class Config
{
private:
    SecretKey mSecretKey;
    bool mIsValidator;
    BCPQuorumSet mBCPQuorumSet;

public:
    this()
    {

    }
    
    static const string OWLCHAIN_CORE_VERSION = "v0.0.1";
    static const int CURRENT_LEDGER_PROTOCOL_VERSION = 8;

    // non configurable
    bool FORCE_BCP = false;
    int LEDGER_PROTOCOL_VERSION = CURRENT_LEDGER_PROTOCOL_VERSION;

    uint32 OVERLAY_PROTOCOL_MIN_VERSION = 5;
    uint32 OVERLAY_PROTOCOL_VERSION = 5;

    string VERSION_STR = OWLCHAIN_CORE_VERSION;
    uint32 DESIRED_BASE_RESERVE = 100000000;

    // configurable
    bool RUN_STANDALONE = false;
    bool MANUAL_CLOSE = false;
    bool CATCHUP_COMPLETE = false;
    bool CATCHUP_RECENT = 0;
    bool MAINTENANCE_ON_STARTUP = true;
    bool ARTIFICIALLY_GENERATE_LOAD_FOR_TESTING = false;
    bool ARTIFICIALLY_ACCELERATE_TIME_FOR_TESTING = false;
    bool ARTIFICIALLY_SET_CLOSE_TIME_FOR_TESTING = 0;
    bool ARTIFICIALLY_PESSIMIZE_MERGES_FOR_TESTING = false;
    bool ALLOW_LOCALHOST_FOR_TESTING = false;
    int32 FAILURE_SAFETY = -1;
    bool UNSAFE_QUORUM = false;

    string LOG_FILE_PATH = "owlchain-core.%datetime{%Y.%M.%d-%H:%m:%s}.log";
    string BUCKET_DIR_PATH = "buckets";

    uint32 DESIRED_BASE_FEE = 100;
    uint32 DESIRED_MAX_TX_PER_LEDGER = 50;


    @property SecretKey NODE_SEED()
    {
        return mSecretKey;
    }

    @property bool NODE_IS_VALIDATOR()
    {
        return mIsValidator;
    }

    @property ref  BCPQuorumSet QUORUM_SET()
    {
        return mBCPQuorumSet;
    }

    string toShortString(ref PublicKey pk) 
    {
        return "";
    }

    string toStrKey(ref PublicKey pk) 
    {
        return "";
    }

    string toStrKey2(ref PublicKey pk, ref bool isAlias) 
    {
        return "";
    }

    bool resolveNodeID(ref string s, ref PublicKey retKey) const
    {
        return false;
    }
}
