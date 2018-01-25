import re
from org.zaproxy.zap.extension.script import ScriptVars

''' find posible SSRF using Hunt Methodology'''

def scan(ps, msg, src):
    # Test the request and/or response here
    if ScriptVars.getGlobalVar("hunt_pssrf") is None:
        ScriptVars.setGlobalVar("hunt_pssrf","init")

    if (msg and msg.getHistoryRef().getHistoryType()<=2):
        # Change to a test which detects the vulnerability
        # raiseAlert(risk, int reliability, String name, String description, String uri,
        # String param, String attack, String otherInfo, String solution, String evidence,
        # int cweId, int wascId, HttpMessage msg)
        # risk: 0: info, 1: low, 2: medium, 3: high
        # reliability: 0: falsePositive, 1: suspicious, 2: warning

        words = ['dest','redirect','uri','path','continue','url','window','next','data','reference','site','html','val','validate','domain','callback','return','page','feed','host','port','to','out','view','dir','show','navigation','open']
        result = []
        uri = msg.getRequestHeader().getURI().toString()
        params = msg.getParamNames()
        params = [element.lower() for element in params]

        base_uri = re.search('https?:\/\/([^/]+)(\/[^?#=]*)',uri)

        if base_uri:
            base_uri = str( base_uri.group() )
            regex = base_uri + str(params)
            globalvar = ScriptVars.getGlobalVar("hunt_pssrf")
            if regex not in globalvar:
                ScriptVars.setGlobalVar("hunt_pssrf","" + globalvar + ' , ' + regex)

                for x in words:
                    y = re.compile(".*"+x)
                    if len(filter(y.match, params))>0:
                        result.append(x)

                if result:
                    ps.raiseAlert(1, 1, 'Possible SSRF', 'HUNT located the ' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often susceptible to Server Side Request Forgery (and sometimes URL redirects). HUNT recommends further manual analysis of the parameter in question.\n\nFor Server Side Request Forgery HUNT recommends the following resources to aid in manual testing:\n\n- Server-side browsing considered harmful - Nicolas Gregoire: http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf \n- How To: Server-Side Request Forgery (SSRF) - Jobert Abma: https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF \n- SSRF Examples from ngalongc/bug-bounty-reference: https://github.com/ngalongc/bug-bounty-reference#server-side-request-forgery-ssrf \n- Safebuff SSRF Tips: http://blog.safebuff.com/2016/07/03/SSRF-Tips/ \n- The SSRF Bible: https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit',
                    msg.getRequestHeader().getURI().toString(),
                    ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);
