plugins { application }
java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }
dependencies {
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
application { mainClass = "com.example.svc.Main" }
tasks.test { useJUnitPlatform() }
