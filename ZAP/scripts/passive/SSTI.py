import re

''' find posible Server Side Template Injection using Hunt Methodology'''

def scan(ps, msg, src):
  # Test the request and/or response here
  if (True):
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePositive, 1: suspicious, 2: warning
	
	words = ['template','preview','id','view','activity','name','content','redirect']
	
	result = []

	params = msg.getParamNames()
	params = [element.lower() for element in params]

	for x in words:
		y = re.compile(".*"+x)
		if len(filter(y.match, params))>0:
			result.append(x)

	if result:
		ps.raiseAlert(1, 1, 'Possible SSTI', 'HUNT located the ' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often susceptible to Server Side Template Injection. HUNT recommends further manual analysis of the parameter in question.', 
     	 msg.getRequestHeader().getURI().toString(),
     	 ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);
