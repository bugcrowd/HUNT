# HUNT Burp Suite Plugin

HUNT is a Burp extension to:

1. Identify common parameters vulnerable to certain vulnerability classes. 
2. Organize testing methodologies inside of Burp Suite.

## HUNT Scanner (hunt_scanner.py)

This extension does not test these parameters but rather alerts on them so that a bug hunter can test them manually (thoroughly). For each class of vulnerability, Bugcrowd has identified common parameters or functions associated with that vulnerability class. We also provide curated resources in the issue description to do thorough manual testing of these vulnerability classes.

## HUNT Methodology (hunt_methodology.py)

This extension XXX 

## Getting Started with HUNT Scanner

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
* ~~Template Injection~~
* ~~External Entity Injection~~
* ~~Malicious File Upload~~


### TODO
* Change regex for parameter names to include user_id instead of just id
* Add functionality to send request/response to other Burp tabs like Repeater
* Add PCI and WAHH methodology JSON files
* Add more text for advisory in scanner window
* Add more description and resources in methodology window

## Authors

* **Jason Haddix** - *Initial work* 
* **JP Villanueva** - *Initial work* 
* **Ryan Black** - *Initial work* 
* **Fatih Egbatan** - *Initial work*
* **Vishal Shah** - *Initial work*


## License



## Acknowledgments

* Hat tip to anyone who's code was used
* Inspiration
* etc
