import re
from org.zaproxy.zap.extension.script import ScriptVars

''' find posible Server Side Template Injection using Hunt Methodology'''

def scan(ps, msg, src):
    # Test the request and/or response here
    if ScriptVars.getGlobalVar("hunt_dlp") is None:
        ScriptVars.setGlobalVar("hunt_dlp","init")

    if (msg and msg.getHistoryRef().getHistoryType()<=2):
        # Change to a test which detects the vulnerability
        # raiseAlert(risk, int reliability, String name, String description, String uri,
        # String param, String attack, String otherInfo, String solution, String evidence,
        # int cweId, int wascId, HttpMessage msg)
        # risk: 0: info, 1: low, 2: medium, 3: high
        # reliability: 0: falsePositive, 1: suspicious, 2: warning

        words = ['access','admin','dbg','debug','edit','grant','test','alter','clone','create','delete','disable','enable','exec','execute','load','make','modify','rename','reset','shell','toggle','adm','root','cfg','config']
        result = []
        uri = msg.getRequestHeader().getURI().toString()
        params = msg.getParamNames()
        params = [element.lower() for element in params]

        base_uri = re.search('https?:\/\/([^/]+)(\/[^?#=]*)',uri)

        if base_uri:
            base_uri = str( base_uri.group() )
            regex = base_uri + str(params)
            globalvar = ScriptVars.getGlobalVar("hunt_dlp")
            if regex not in globalvar:
                ScriptVars.setGlobalVar("hunt_dlp","" + globalvar + ' , ' + regex)

                for x in words:
                    y = re.compile(".*"+x)
                    if len(filter(y.match, params))>0:
                        result.append(x)

                if result:
                    ps.raiseAlert(1, 1, 'Possible Debug & Logic Parameters', 'HUNT located the' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often associated to debug,  access, or critical functionality in applications. \nHUNT recommends further manual analysis of the parameter in question.',
                    msg.getRequestHeader().getURI().toString(),
                    ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);
