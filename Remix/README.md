# HUNT Remix

A complete rewrite of the HUNT scanner. 

## Burp Extension
The [Burp Suite](https://portswigger.net/burp) extension works in both the Community (Free) and Professional versions. 

## Features:
* Passively scan for common parameters vulnerable to vulnerabilities 

![HUNT Remix](/Remix/images/huntremix.png)

## ToDo
- [ ] OWASP ZAP Plugin
- [ ] Ability to add and modify rules
- [ ] Identify reflected parameters

## Install the HUNT Remix Burp Suite Extension

### Download or build the extension
#### Option 1: Download release
You can find the latest release (JAR file) [here](https://github.com/cak/HUNT/releases). 

#### Option 2: Build the extension

```sh
gradle build jar
```

Extension JAR will be located at: `build/libs/huntburpremix-x.x.x.jar`

### Load the extension
1. Open Burp Suite
2. Go to Extender tab
3. Burp Extensions -> Add
4. Load huntburpremix-x.x.x.jar


### Usage
#### Passive scanning
1. Set scope
2. Manually navigate or spider the application
3. Requests will vulnerable parameters be added to the `HUNT RMX` tab.
4. Select and right click on request to view details about the vulnerable parameter.  

## Credits
HUNT Remix was created by [cak](https://github.com/cak) [[projects](https://derail.io)] utilizing the research from [JP Villanueva](https://github.com/swagnetow), [Jason Haddix](https://github.com/jhaddix) and team at [Bugcrowd](https://www.bugcrowd.com). 
 
