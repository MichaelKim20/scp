module owlchain.database.statementContext;

class session
{
    this()
    {

    }

}
class Statement
{
public:
    this(session s)
    {

    }
    void alloc()   
    {
        
    }

    void bind()
    {

    }

    void reset()
    {

    }

    void exchange(string i)
    {

    }
    void clean_up(bool freeBackend=true)
    {

    }

    void prepare(string quer)
    {

    }

    bool execute(bool withDataExchange = false)
    {
        return true;
    }

    long get_affected_rows()
    {
        return 0;
    }

    bool fetch()
    {
        return true;
    }

    bool got_data() 
    { 
        return true; 
    }

    void describe()       
    { 
    }
    
    void set_row()
    { 
    
    }
    
    void exchange_for_rowset()
    {
    
    }
}

class StatementContext
{
private:
    Statement mStmt;

public:
    this(Statement stmt)
    {
    mStmt = stmt;
    mStmt.clean_up(false);
    }
    this(StatementContext other)
    {
        mStmt = other.mStmt;
        other.mStmt.reset();
    }
    ~this()
    {
        if (mStmt)
        {
            mStmt.clean_up(false);
        }
    }
    Statement getStatement()
    {
        return mStmt;
    }
}