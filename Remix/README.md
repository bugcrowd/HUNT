# HUNT v2 (Remix)

A complete rewrite of the HUNT scanner.

## Burp Extension

The [Burp Suite](https://portswigger.net/burp) extension works in both the Community (Free) and Professional versions.

## ZAP Extension

The [OWASP Zed Attack Proxy (ZAP)](https://www.zaproxy.org) add-on works on that latest ZAP version (2.9.0).

## Features

- Passively scan for potentially vulnerable parameters

## Screenshots

### Burp Suite

![HUNT v2 Burp](/Remix/images/huntrmxburp.png)

### ZAP

![HUNT v2 ZAP](/Remix/images/huntrmxzap.png)

## ToDo

- [x] OWASP ZAP Plugin
=======

The [Burp Suite](https://portswigger.net/burp) extension works in both the Community (Free) and Professional versions.

## Features:

- Passively scan for potentially vulnerable parameters

#### Screenshot

![HUNT Remix](/Remix/images/huntrmxburp.png)

## ToDo

- [ ] OWASP ZAP Plugin
- [ ] Ability to add and modify rules
- [ ] Identify reflected parameters

## Install the HUNT v2 Burp Suite Extension

### Download or build the extension

#### Option 1: Download extension

You can find the latest release (JAR file) [here](https://github.com/bugcrowd/HUNT/releases).

#### Option 2: Build the extension

```sh
gradle build fatJar
```

Extension JAR will be located at: `build/libs/hunt-x.x.x.jar`

### Load the extension

1. Open Burp Suite
2. Go to Extender tab
3. Burp Extensions -> Add

4. Load hunt-x.x.x.jar

## Install the HUNT v2 ZAP add-on

### Download or build the add-on

#### Option 1: Download add-on

You can find the latest release (ZAP file) [here](https://github.com/bugcrowd/HUNT/releases).

#### Option 2: Build the add-on

```sh
gradle build
```

Add-on ZAP file will be located at: `./build/zapAddOn/bin`

### Load the add-on

1. Open OWASP ZAP
2. File
3. Load Add-on file
4. Select HUNT `.zap` file

## Usage

### Passive scanning

=======
4. Load HUNT-x.x.jar

### Usage

#### Passive scanning

1. Set scope
2. Manually navigate or spider the application
3. Requests will vulnerable parameters be added to the `HUNT` tab.
4. Select and right click on request to view details about the vulnerable parameter.

## Credits


HUNT v2 (Remix) was created by [cak](https://github.com/cak) [[projects](https://derail.io)] utilizing the research from [JP Villanueva](https://github.com/swagnetow), [Jason Haddix](https://github.com/jhaddix) and team at [Bugcrowd](https://www.bugcrowd.com).