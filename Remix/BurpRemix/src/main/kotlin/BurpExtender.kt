package burp

class BurpExtender : IBurpExtender {
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        val tab = HuntTab(callbacks)
        callbacks.registerHttpListener(HuntListener(callbacks, tab))
        callbacks.stdout.write("HUNT Remix - v0.1.0".toByteArray())
        callbacks.stdout.write("\nOriginally by: JP Villanueva, Jason Haddix and team at Bugcrowd".toByteArray())
        callbacks.stdout.write("\nRepo: https://github.com/bugcrowd/HUNT".toByteArray())
        callbacks.stdout.write("\nRemixed by: Caleb Kinney (derail.io)".toByteArray())
        callbacks.setExtensionName("HUNT Remix")
        callbacks.addSuiteTab(tab)
    }
}