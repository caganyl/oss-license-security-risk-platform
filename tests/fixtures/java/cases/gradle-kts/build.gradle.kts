plugins {
    kotlin("jvm") version "2.0.0"
    id("com.google.devtools.ksp") version "2.0.0-1.0.21"
}

val ktorVersion = "2.3.11"

dependencies {
    implementation(kotlin("stdlib"))
    implementation("io.ktor:ktor-server-core:$ktorVersion")
    implementation("io.ktor:ktor-server-netty:${ktorVersion}")
    implementation("com.squareup.okhttp3:okhttp:${libs.versions.okhttp.get()}")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation(group = "com.google.code.gson", name = "gson", version = "2.11.0")
    implementation(libs.androidx.core.ktx)
    implementation(libs.bundles.compose)
    implementation(platform("androidx.compose:compose-bom:2024.05.00"))
    implementation("androidx.compose.ui:ui")
    api("com.squareup.moshi:moshi:1.+")
    ksp("com.squareup.moshi:moshi-kotlin-codegen:1.15.1")
    kapt("com.google.dagger:dagger-compiler:2.51.1")
    compileOnly("javax.annotation:jsr250-api:1.0")
    runtimeOnly("ch.qos.logback:logback-classic:1.5.6") {
        exclude(group = "org.slf4j", module = "slf4j-api")
    }
    implementation("io.github.example:strict:1.2.3") {
        version {
            strictly("1.2.3")
        }
    }
    testImplementation(kotlin("test"))
    testImplementation("io.mockk:mockk:1.13.11")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    kspTest("com.squareup.moshi:moshi-kotlin-codegen:1.15.1")
    implementation(project(":shared"))
}

tasks.test {
    useJUnitPlatform()
}
