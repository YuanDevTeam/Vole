plugins {
    id("com.android.application") version "9.5.2"
}

android {
    namespace = "io.github.yuandevteam.vole.jsprobe"
    compileSdk {
        version = release(37) { minorApiLevel = 2 }
    }

    defaultConfig {
        applicationId = "io.github.yuandevteam.vole.jsprobe"
        minSdk = 26
        targetSdk = 36
    }

    sourceSets["main"].jniLibs.directories.add(
        providers.gradleProperty("voleJniLibs").getOrElse("../../dist/android")
    )
    sourceSets["main"].assets.directories.add(layout.buildDirectory.dir("fixture").get().asFile.path)
}

val copyFixture = tasks.register<Sync>("copyFixture") {
    from("../fixtures/http-js-platform.yaml")
    into(layout.buildDirectory.dir("fixture"))
}
tasks.named("preBuild") { dependsOn(copyFixture) }

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:5.5.1")
}
