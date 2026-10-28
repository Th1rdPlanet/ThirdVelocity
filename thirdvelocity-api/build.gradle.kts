plugins {
    `java-library`
    `maven-publish`
}

group = "ru.moonlightproject"
version = "1.0.0"

java {
    withJavadocJar()
    withSourcesJar()
}

dependencies {
    compileOnlyApi(libs.jspecify)
}

tasks.withType<JavaCompile>().configureEach {
    // Plugins built for Java 21 must be able to link against the API.
    options.release.set(21)
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        encoding = "UTF-8"
        addStringOption("Xdoclint:none", "-quiet")
    }
}

// The API follows its own documentation rules (docs/api.md) instead of the upstream checkstyle.
tasks.withType<Checkstyle>().configureEach { enabled = false }

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "thirdvelocity-api"
            from(components["java"])
            pom {
                name.set("ThirdVelocity API")
                description.set("Java API of the ThirdVelocity proxy: bans, GeoIP, IP reputation, alts, client detection")
                url.set("https://github.com/Th1rdPlanet/ThirdVelocity")
                licenses {
                    license {
                        name.set("GPL-3.0-or-later")
                        url.set("https://www.gnu.org/licenses/gpl-3.0.html")
                    }
                }
            }
        }
    }
}
