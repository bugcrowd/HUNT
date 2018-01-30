import re
from org.zaproxy.zap.extension.script import ScriptVars

''' find posible File Inclusion using Hunt Methodology'''

def scan(ps, msg, src):
    # Test the request and/or response here
    if ScriptVars.getGlobalVar("hunt_pfi") is None:
        ScriptVars.setGlobalVar("hunt_pfi","init")

    if (msg and msg.getHistoryRef().getHistoryType()<=2):
        # Change to a test which detects the vulnerability
        # raiseAlert(risk, int reliability, String name, String description, String uri,
        # String param, String attack, String otherInfo, String solution, String evidence,
        # int cweId, int wascId, HttpMessage msg)
        # risk: 0: info, 1: low, 2: medium, 3: high
        # reliability: 0: falsePositive, 1: suspicious, 2: warning

        words = ['file','document','folder','root','path','pg','style','pdf','template','php_path','doc']
        result = []
        uri = msg.getRequestHeader().getURI().toString()
        params = msg.getParamNames()
        params = [element.lower() for element in params]

        base_uri = re.search('https?:\/\/([^/]+)(\/[^?#=]*)',uri)

        if base_uri:
            base_uri = str( base_uri.group() )
            regex = base_uri + str(params)
            globalvar = ScriptVars.getGlobalVar("hunt_pfi")
            if regex not in globalvar:
                ScriptVars.setGlobalVar("hunt_pfi","" + globalvar + ' , ' + regex)

                for x in words:
                    y = re.compile(".*"+x)
                    if len(filter(y.match, params))>0:
                        result.append(x)

                if result:
                    ps.raiseAlert(1, 1, 'Possible File Inclusion or Path Traversal', 'HUNT located the ' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often susceptible to File Inclusion or Path Traversal. HUNT recommends further manual analysis of the parameter in question. Also note that several parameters from this section and SSRF might overlap or need testing for both vulnerability categories.\n\nFor File Inclusion or Path Traversal HUNT recommends the following resources to aid in manual testing:\n\n- The Web Application Hackers Handbook: Chapter 10\n- LFI Cheat Sheet: https://highon.coffee/blog/lfi-cheat-sheet/ \n- Gracefuls Path Traversal Cheat Sheet: Windows: https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/ \n- Gracefuls Path Traversal Cheat Sheet: Linux: https://www.gracefulsecurity.com/path-traversal-cheat-sheet-linux/',
                    msg.getRequestHeader().getURI().toString(),
                    ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);
