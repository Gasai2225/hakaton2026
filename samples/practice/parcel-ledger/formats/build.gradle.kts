plugins { `java-library` }
configurations.compileClasspath { resolutionStrategy.activateDependencyLocking() }
val archive = providers.gradleProperty("archiveRelease").get()

dependencies {
    compileOnly("org.json:json:2023+")
    runtimeOnly("org.apache.commons:commons-compress:$archive")
    add("runtimeOnly", "commons-net:commons-net:3.8.0")
    runtimeOnly("org.jsoup:jsoup:1.14.2")
}
