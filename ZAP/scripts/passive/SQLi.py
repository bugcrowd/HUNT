import re
from org.zaproxy.zap.extension.script import ScriptVars

''' find posible SQLi using Hunt Methodology'''

def scan(ps, msg, src):
    # Test the request and/or response here
    if ScriptVars.getGlobalVar("hunt_psql") is None:
        ScriptVars.setGlobalVar("hunt_psql","init")

    if (msg and msg.getHistoryRef().getHistoryType()<=2):
        # Change to a test which detects the vulnerability
        # raiseAlert(risk, int reliability, String name, String description, String uri,
        # String param, String attack, String otherInfo, String solution, String evidence,
        # int cweId, int wascId, HttpMessage msg)
        # risk: 0: info, 1: low, 2: medium, 3: high
        # reliability: 0: falsePositive, 1: suspicious, 2: warning

        words = ['id','select','report','role','update','query','user','name','sort','where','search','params','process','row','view','table','from','sel','results','sleep','fetch','order','keyword','column','field','delete','string','number','filter']
        result = []
        uri = msg.getRequestHeader().getURI().toString()
        params = msg.getParamNames()
        params = [element.lower() for element in params]

        base_uri = re.search('https?:\/\/([^/]+)(\/[^?#=]*)',uri)

        if base_uri:
            base_uri = str( base_uri.group() )
            regex = base_uri + str(params)
            globalvar = ScriptVars.getGlobalVar("hunt_psql")
            if regex not in globalvar:
                ScriptVars.setGlobalVar("hunt_psql","" + globalvar + ' , ' + regex)

                for x in words:
                    y = re.compile(".*"+x)
                    if len(filter(y.match, params))>0:
                        result.append(x)

                if result:
                    ps.raiseAlert(1, 1, 'Possible SQLi', 'HUNT located the parameter inside of your application traffic. The parameter is most often susceptible to SQL Injection. HUNT recommends further manual analysis of the parameter in question.\n\nFor SQL Injection HUNT references The Bug Hunters Methodology SQL Injection references table:\n\n- PentestMonkeys MySQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet \n\n- Reiners MySQL Injection Filter Evasion: https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/ \n- EvilSQLs Error/Union/Blind MSSQL Cheat Sheet: http://evilsql.com/main/page2.php \n- PentestMonkeys MSSQL SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet \n- PentestMonkeys Oracle SQL Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet \n- PentestMonkeys PostgreSQL Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet \n- Access SQL Injection Cheat Sheet: http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html \n- PentestMonkeys Ingres SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet \n- PentestMonkeys DB2 SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet \n- PentestMonkeys Informix SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet \n- SQLite3 Injection Cheat Sheet: https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet \n- Ruby on Rails (ActiveRecord) SQL Injection Guide: https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet',
                    msg.getRequestHeader().getURI().toString(),
                    ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '',
                    '', 0, 0, msg);
