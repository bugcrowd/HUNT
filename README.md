# HUNT Proxy Extension

![HUNT Logo](/images/logo.png)

HUNT is a proxy extension to:

1. Identify common parameters vulnerable to certain vulnerability classes (HUNT Scanner, availible for Burp Suite PRO and ZAProxy). 
2. Organize testing methodologies (currently avalible only inside of Burp Suite).

### HUNT Scanner Vulnerability Classes

* SQL Injection
* Local/Remote File Inclusion & Path Traversal
* Server Side Request Forgery & Open Redirect
* OS Command Injection
* Insecure Direct Object Reference
* Server Side Template Injection
* Logic & Debug Parameters
* ~~Cross Site Scripting~~
* ~~External Entity Injection~~
* ~~Malicious File Upload~~


### TODO
* ~~Change regex for parameter names to include user_id instead of just id~~
* ~~Search in scanner window~~
* ~~Highlight param in scanner window~~
* Implement script name checking, REST URL support, JSON & XML post-body params.
* Support normal convention of Request tab: Raw, Params, Headers, Hex sub-tabs inside scanner
* Add more methodology JSON files:
  * ~~Web Application Hacker's Handbook~~
  * PCI
  * HIPAA
  * CREST
  * OWASP Top Ten
  * OWASP Application Security Verification Standard
  * Penetration Testing Execution Standard
  * Burp Suite Methodology
* Add more text for advisory in scanner window
* Add more descriptions and resources in methodology window
* Add functionality to send request/response to other Burp tabs like Repeater

## Authors

* **JP Villanueva**
* **Jason Haddix**
* **Ryan Black**
* **Fatih Egbatan**
* **Vishal Shah**


# HUNT for Burp Suite PRO

## HUNT Scanner (hunt_scanner.py)

![HUNT Scanner](/images/scanner.png)

This extension does not test these parameters but rather alerts on them so that a bug hunter can test them manually (thoroughly). For each class of vulnerability, Bugcrowd has identified common parameters or functions associated with that vulnerability class. We also provide curated resources in the issue description to do thorough manual testing of these vulnerability classes.

## HUNT Methodology (hunt_methodology.py)

![HUNT Methodology](/images/methodology.png)

This extension allows testers to send requests and responses to a Burp tab called "HUNT Methodology". This tab contains a tree on the left side that is a visual representation of your testing methodology. By sending request/responses here testers can organize or attest to having done manual testing in that section of the application or having completed a certain methodology step.

## Getting Started with HUNT for Burp Suite

1. First ensure you have the latest standalone Jython JAR set up under "Extender" -> "Options".
2. Add HUNT via "Extender" -> "Extensions".
3. HUNT Scanner will begin to run across traffic that flows through the proxy.

Important to note, HUNT Scanner leverages the passive scanning API. Here are the conditions under which passive scan checks are run: 

* First request of an active scan
* Proxy requests
* Any time "Do a passive scan" is selected from the context menu

*Passive scans are not run on the following:*

* On every active scan response
* On Repeater responses
* On Intruder responses
* On Sequencer responses
* On Spider responses

Instead, the standard workflow would be to set your scope, run Burp Spider from Target tab, then right-click "Passively scan selected items".

# HUNT Scanner for ZAP Proxy (Alpha - Contributed by Ricardo Lobo @_sbzo)

1. Find the "Manage Addons" icon, ensure you have ``` Python Scripting ``` installed.
2. Ensure "show All Tabs" icon is clicked
3. Click the ```Tools``` menu, navigate to the ```Options``` section. Select ```Passive Scanner``` and check the box ```Scan messages only in scope``` and then ```OK```
4. Click into the ``` Scripts ``` tab (next to the  ``` Sites ``` tab)
5. Click the ```load script``` icon and load each python script into ZAP. They should appear under ```passive rules```
6. Right click on each script under ```passive rules``` and enable them and save them
7. Browse sites and recieve alerts!



## License

Licensed with the Apache 2.0 License [here](https://github.com/bugcrowd/HUNT/blob/master/license)
