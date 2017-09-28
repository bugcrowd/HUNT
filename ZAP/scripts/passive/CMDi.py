import re

''' find posible CDMi using Hunt Methodology'''

def scan(ps, msg, src):
  # Test the request and/or response here
  if (True):
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePositive, 1: suspicious, 2: warning
	
	words = ['daemon','host' ,'upload','dir','execute','download','log','ip','cli','cmd']
	
	result = []
	
	params = msg.getParamNames()
	params = [element.lower() for element in params]

	for x in words:
		y = re.compile(".*"+x)
		if len(filter(y.match, params))>0:
			result.append(x)
		
	if result:
		ps.raiseAlert(1, 1, 'Possible CMDi', 'HUNT located the <b>$param$</b> parameter inside of your application traffic. The <b>$param$</b> parameter is most often susceptible to OS Command Injection. HUNT recommends further manual analysis of the parameter in question.<br><br>For OS Command Injection HUNT recommends the following resources to aid in manual testing:<br><br><a href=https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)>(OWASP) Testing for OS Command Injection</a><br><a href=https://www.hackerone.com/blog/how-to-command-injections>Joberts How To Command Injection</a><br><a href=https://github.com/commixproject/commix>Commix Command Injection Tool</a><br><a href=https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/os-cmd-execution>The FuzzDB OS CMD Exec section</a><br><a href=https://ferruh.mavituna.com/unix-command-injection-cheat-sheet-oku/>Ferruh Mavitunas CMDi Cheat Sheet</a><br>The Web Application Hackers Handbook: Chapter 10', 
     	 msg.getRequestHeader().getURI().toString(), 
     	 ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);
