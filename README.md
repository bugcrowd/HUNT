# HUNT Burp Suite Extentsion

![HUNT Logo](/images/logo.png)

HUNT is a Burp extension to:

1. Identify common parameters vulnerable to certain vulnerability classes. 
2. Organize testing methodologies inside of Burp Suite.

## HUNT Scanner (hunt_scanner.py)

![HUNT Scanner](/images/scanner.png)

This extension does not test these parameters but rather alerts on them so that a bug hunter can test them manually (thoroughly). For each class of vulnerability, Bugcrowd has identified common parameters or functions associated with that vulnerability class. We also provide curated resources in the issue description to do thorough manual testing of these vulnerability classes.

## HUNT Methodology (hunt_methodology.py)

![HUNT Methodology](/images/methodology.png)

This extension allows testers to send requests and responses to a Burp tab called "HUNT Methodology". This tab contains a tree on the left side that is a visual representation of your testing methodology. By sending request/responses here testers can organize or attest to having done manual testing in that section of the application or having completed a certain methodology step.

## Getting Started with HUNT

1. First ensure you have the Jython standalone jar set up under "Extender" -> "Options"
2. Add HUNT via "Extender" -> "Extensions"
3. HUNT Scanner will begin to run across traffic that flows through the proxy.

Important to note, HUNT Scanner leverages the passive scanning API. Here are the conditions under which passive scan checks are run: 

* First request of an active scan
* Proxy requests
* Any time 'Do a passive scan' is selected from the context menu

*Passive scans are not run:*

* On every active scan response
* On Repeater responses
* On Intruder responses
* On Sequencer responses
* On Spider responses

### HUNT Scanner Vulnerability Classes

* SQL Injection
* Local/Remote File Inclusion & Path Traversal
* Insecure Direct Object Reference
* Server Side Request Forgery & Open Redirect
* Command Injection
* ~~Cross Site Scripting~~
* Template Injection
* ~~External Entity Injection~~
* ~~Malicious File Upload~~


### TODO
* Implement script name checking, REST URL support, JSON & XML post-body params.
* Highlight param in scanner window
* Search in scanner window
* Support normal convention of Request tab: Raw, Params, Headers, Hex sub-tabs inside scanner
* Change regex for parameter names to include user_id instead of just id
* Add PCI and WAHH methodology JSON files
* Add more text for advisory in scanner window
* Add more description and resources in methodology window
* Add functionality to send request/response to other Burp tabs like Repeater

## Authors

* **JP Villanueva**
* **Jason Haddix**
* **Ryan Black**
* **Fatih Egbatan**
* **Vishal Shah**


## License

Licesed with the apache 2.0 license here: https://choosealicense.com/licenses/apache-2.0/
