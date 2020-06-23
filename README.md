# HUNT Suite Proxy Extensions 

![HUNT Logo](/images/logo.png)

### What is HUNT Suite?
* HUNT Suite is a collection of Burp Suite Pro/Free and OWASP ZAP extensions.
* Identifies common parameters vulnerable to certain vulnerability classes (Burp Suite Pro and OWASP ZAP). 
* Organize testing methodologies (Burp Suite Pro and Free).

### HUNT Parameter Scanner - Vulnerability Classes

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

## Contributors
* **Ryan Black**
* **Fatih Egbatan**
* **Vishal Shah**


# HUNT Suite for Burp Suite Pro/Free

## HUNT Parameter Scanner (hunt_scanner.py)

![HUNT Scanner](/images/scanner.png)

This extension does not test these parameters, but rather alerts on them so that a bug hunter can test them manually. For each class of vulnerability, Bugcrowd has identified common parameters or functions associated with that vulnerability class. We also provide curated resources in the issue description to do thorough manual testing of these vulnerability classes.

## HUNT Testing Methodology (hunt_methodology.py)

![HUNT Methodology](/images/methodology.png)

This extension allows testers to send requests and responses to a Burp Suite tab called "HUNT Methodology". This tab contains a tree on the left side that is a visual representation of your testing methodology. By sending request/responses here testers can organize or attest to having done manual testing in that section of the application or having completed a certain methodology step.

# Installing HUNT Suite for Burp Suite Pro/Free

## Getting Started
1. Download the [latest standalone](http://www.jython.org/downloads.html) Jython `jar`.
2. Navigate to *Extender -> Options*. 
  ![Adding Jython](/images/jython.png)
  * Locate the section called *Python Environment*.
  * Add the location of the Jython `jar` by clicking *Select file...*.
3. Navigate to *Extender -> Extensions*.
  ![Adding Extension](/images/extension.png)
  * Click *Add*.
  * Locate *Extension Details*.
    * Select "Python" as the *Extension Type*.
    * Click "Select file..." to select the location of where the extension is located in your filesystem.
    * Do this for both the HUNT Parameter Scanner and HUNT Testing Methodology
4. The HUNT Parameter Scanner will begin to run across traffic that flows through the proxy.

## Setting Scope
This is an important step to set your testing scope as the passive scanner is incredibly noisy. Instead of polluting the Scanner window, the HUNT Parameter Scanner creates its own window with its own findings.
1. Navigate to *Target -> Scope*.
  ![Target Scope](/images/target_scope.png)
  * Click the "Use advanced scope control" checkbox.
  * Click add to include to your scope.
2. Navigate to *Scanner -> Live scanning*.
  * Under the "Live Passive Scanning" section, click "Use suite scope \[defined in the target tab\]".
  ![Passive Scanner](/images/passive_scanner.png)

## Important Notes
HUNT Parameter Scanner leverages the passive scanning API within Burp. Here are the conditions under which passive scan checks are run: 
* First request of an active scan
* Proxy requests
* Any time "Do a passive scan" is selected from the context menu

**Passive scans are not run on the following:**
* On every active scan response
* On Repeater responses
* On Intruder responses
* On Sequencer responses
* On Spider responses

# HUNT Scanner for OWASP ZAP (Alpha - Contributed by Ricardo Lobo @_sbzo)
Hunt scanner is included into community scripts for ZAP Proxy.

1. Find the "Manage Addons" icon, ensure you have ``` Python Scripting ``` and ``` Community Scripts ``` installed.
2. Ensure "show All Tabs" icon is clicked
3. Click the ```Tools``` menu, navigate to the ```Options``` section. Select ```Passive Scanner``` and check the box ```Scan messages only in scope``` and then ```OK```
4. Click into the ``` Scripts ``` tab (next to the  ``` Sites ``` tab)
5. Look for ``` Hunt.py ``` should appear under ```passive rules```
6. Right click in the script under ```passive rules``` and enable it and save it
7. Browse sites and receive alerts from the sites included in contexts!

## License
Licensed with the Apache 2.0 License [here](https://github.com/bugcrowd/HUNT/blob/master/license)
