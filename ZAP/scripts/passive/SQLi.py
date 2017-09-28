import re

''' find posible SQLi using Hunt Methodology'''

def scan(ps, msg, src):
  # Test the request and/or response here
  if (True):
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePositive, 1: suspicious, 2: warning
	
	words = ['id','select','report','role','update','query','user','name','sort','where','search','params','process','row','view','table','from','sel','results','sleep','fetch','order','keyword','column','field','delete','string','number','filter']
	
	result = []

	params = msg.getParamNames()
	params = [element.lower() for element in params]

	for x in words:
		y = re.compile(".*"+x)
		if len(filter(y.match, params))>0:
			result.append(x)

	if result:
		ps.raiseAlert(1, 1, 'Possible SQLi', 'HUNT located the parameter inside of your application traffic. The parameter is most often susceptible to SQL Injection. HUNT recommends further manual analysis of the parameter in question.<br><br>For SQL Injection HUNT references The Bug Hunters Methodology SQL Injection references table:<br><br><a href=http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet>PentestMonkeys MySQL Injection Cheat Sheet</a><br><a href=https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/>Reiners MySQL Injection Filter Evasion</a><br><a href=http://evilsql.com/main/page2.php>EvilSQLs Error/Union/Blind MSSQL Cheat Sheet</a><br><a href=http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet>PentestMonkeys MSSQL SQL Injection Cheat Sheet</a><br><a href=http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet>PentestMonkeys Oracle SQL Cheat Sheet<br>PentestMonkeys PostgreSQL Cheat Sheet</a><br><a href=http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet>Access SQL Injection Cheat Sheet</a><br><a href=http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html>Access SQL Injection Cheat Sheet</a><br><a href=http://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet>PentestMonkeys Ingres SQL Injection Cheat Sheet</a><br><a href=http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet>PentestMonkeys DB2 SQL Injection Cheat Sheet</a><br><a href=http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet>PentestMonkeys Informix SQL Injection Cheat Sheet</a><br><a href=https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet>SQLite3 Injection Cheat Sheet</a><br><a href=https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet>Ruby on Rails (ActiveRecord) SQL Injection Guide</a>', 
     	 msg.getRequestHeader().getURI().toString(), 
     	 ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);
