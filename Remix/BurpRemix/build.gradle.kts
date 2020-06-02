plugins {
    kotlin("jvm") version "1.3.72"
}

version = "0.0.5"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    implementation("net.portswigger.burp.extender:burp-extender-api:2.1")
}

tasks {
    compileKotlin {
        kotlinOptions.jvmTarget = "1.8"
    }
}

tasks.withType<Jar> {
    from(configurations.compileClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
}