import re
from org.zaproxy.zap.extension.script import ScriptVars

''' find posible CDMi using Hunt Methodology'''

def scan(ps, msg, src):
    # Test the request and/or response here
    if ScriptVars.getGlobalVar("hunt_prce") is None:
        ScriptVars.setGlobalVar("hunt_prce","init")

    if (msg and msg.getHistoryRef().getHistoryType()<=2):
		# Change to a test which detects the vulnerability
		# raiseAlert(risk, int reliability, String name, String description, String uri, 
		# String param, String attack, String otherInfo, String solution, String evidence, 
		# int cweId, int wascId, HttpMessage msg)
		# risk: 0: info, 1: low, 2: medium, 3: high
		# reliability: 0: falsePositive, 1: suspicious, 2: warning
	
		words = ['daemon','host' ,'upload','dir','execute','download','log','ip','cli','cmd']

		result = []
        uri = msg.getRequestHeader().getURI().toString()
		params = msg.getParamNames()
		params = [element.lower() for element in params]

		base_uri = re.search('https?:\/\/([^/]+)(\/[^?#=]*)',uri)

        if base_uri:
            base_uri = str( base_uri.group() )
            regex = base_uri + str(params)
            globalvar = ScriptVars.getGlobalVar("hunt_prce")
            if regex not in globalvar:
                ScriptVars.setGlobalVar("hunt_prce","" + globalvar + ' , ' + regex)
				
			for x in words:
				y = re.compile(".*"+x)
				if len(filter(y.match, params))>0:
					result.append(x)

			if result:
				ps.raiseAlert(1, 1, 'Possible RCE', 'HUNT located the ' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often susceptible to OS Command Injection. HUNT recommends further manual analysis of the parameter in question.\n\nFor OS Command Injection HUNT recommends the following resources to aid in manual testing:\n\n- (OWASP) Testing for OS Command Injection: https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)\n- Joberts How To Command Injection: https://www.hackerone.com/blog/how-to-command-injections \n- Commix Command Injection Tool: https://github.com/commixproject/commix\n-The FuzzDB OS CMD Exec section: https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/os-cmd-execution \n- Ferruh Mavitunas CMDi Cheat Sheet: https://ferruh.mavituna.com/unix-command-injection-cheat-sheet-oku/ \nThe Web Application Hackers Handbook: Chapter 10',
				 msg.getRequestHeader().getURI().toString(),
				 ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);
