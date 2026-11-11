plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing is enabled only when all four env vars are provided (CI).
val releaseKeystorePath = System.getenv("ANDROID_KEYSTORE_PATH")
val releaseKeystorePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
val releaseKeyAlias = System.getenv("ANDROID_KEY_ALIAS")
val releaseKeyPassword = System.getenv("ANDROID_KEY_PASSWORD")
val signingValues = listOf(
    releaseKeystorePath, releaseKeystorePassword, releaseKeyAlias, releaseKeyPassword,
)
val signingEnabled = signingValues.all { !it.isNullOrBlank() }
require(signingEnabled || signingValues.all { it.isNullOrBlank() }) {
    "Set all of ANDROID_KEYSTORE_PATH/ANDROID_KEYSTORE_PASSWORD/" +
        "ANDROID_KEY_ALIAS/ANDROID_KEY_PASSWORD, or none."
}
val releaseKeystore = releaseKeystorePath?.let { file(it) }
if (signingEnabled) {
    require(releaseKeystore != null && releaseKeystore.exists()) {
        "ANDROID_KEYSTORE_PATH does not exist: $releaseKeystore"
    }
}

val appVersionCode = System.getenv("ANDROID_VERSION_CODE")?.let {
    requireNotNull(it.toIntOrNull()) { "ANDROID_VERSION_CODE must be an integer" }
} ?: 1
val appVersionName = System.getenv("ANDROID_VERSION_NAME")?.takeIf { it.isNotBlank() } ?: "1.0"

android {
    namespace = "com.skybadge.relay"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.skybadge.relay"
        minSdk = 26
        targetSdk = 34
        versionCode = appVersionCode
        versionName = appVersionName
    }

    signingConfigs {
        if (signingEnabled) {
            create("release") {
                storeFile = releaseKeystore
                storePassword = releaseKeystorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (signingEnabled) signingConfigs.getByName("release") else null
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
}
