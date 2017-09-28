import re

''' find posible SSRF using Hunt Methodology'''

def scan(ps, msg, src):
  # Test the request and/or response here
  if (True):
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePositive, 1: suspicious, 2: warning
	
	words = ['dest','redirect','uri','path','continue','url','window','next','data','reference','site','html','val','validate','domain','callback','return','page','feed','host','port','to','out','view','dir','show','navigation','open']
	
	result = []

	params = msg.getParamNames()
	params = [element.lower() for element in params]

	for x in words:
		y = re.compile(".*"+x)
		if len(filter(y.match, params))>0:
			result.append(x)

	if result:
		ps.raiseAlert(1, 1, 'Possible SSRF', 'HUNT located the <b>$param$</b> parameter inside of your application traffic. The <b>$param$</b> parameter is most often susceptible to Server Side Request Forgery (and sometimes URL redirects). HUNT recommends further manual analysis of the parameter in question.<br><br>For Server Side Request Forgery HUNT recommends the following resources to aid in manual testing:<br><br><a href=      http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf>Server-side browsing considered harmful - Nicolas Grégoire</a><br><a href=https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF>How To: Server-Side Request Forgery (SSRF) - Jobert Abma</a><br><a href=https://github.com/ngalongc/bug-bounty-reference#server-side-request-forgery-ssrf>SSRF Examples from ngalongc/bug-bounty-reference</a><br><a href=http://blog.safebuff.com/2016/07/03/SSRF-Tips/>safebuff SSRF Tips</a><br><a href=https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit>The SSRF Bible</a>', 
     	 msg.getRequestHeader().getURI().toString(), 
     	 ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);
