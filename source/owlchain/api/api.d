module owlchain.api.api;

interface IAccount 
{
    IAddress getAddress();
    string getAlias();
    ulong getBalance();
    bool send(ulong amount, IAccount receiver);
    bool send(ulong amount, IAddress address);
    bool setFreeze(ulong amount);
}

interface IAddress 
{
    bool isValid();
}
