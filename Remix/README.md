# HUNT Remix

A complete rewrite of the HUNT scanner.

## Burp Extension

The [Burp Suite](https://portswigger.net/burp) extension works in both the Community (Free) and Professional versions.

## Features:

- Passively scan for potentially vulnerable parameters

#### Screenshot

![HUNT Remix](/Remix/images/huntrmxburp.png)

## ToDo

- [ ] OWASP ZAP Plugin
- [ ] Ability to add and modify rules
- [ ] Identify reflected parameters

## Install the HUNT Remix Burp Suite Extension

### Download or build the extension

#### Option 1: Download release

You can find the latest release (JAR file) [here](https://github.com/bugcrowd/HUNT/releases).

#### Option 2: Build the extension

```sh
gradle build fatJar
```

Extension JAR will be located at: `build/libs/hunt-x.x.jar`

### Load the extension

1. Open Burp Suite
2. Go to Extender tab
3. Burp Extensions -> Add
4. Load HUNT-x.x.jar

### Usage

#### Passive scanning

1. Set scope
2. Manually navigate or spider the application
3. Requests will vulnerable parameters be added to the `HUNT` tab.
4. Select and right click on request to view details about the vulnerable parameter.

## Credits

HUNT Remix was created by [cak](https://github.com/cak) [[projects](https://derail.io)] utilizing the research from [JP Villanueva](https://github.com/swagnetow), [Jason Haddix](https://github.com/jhaddix) and team at [Bugcrowd](https://www.bugcrowd.com).
