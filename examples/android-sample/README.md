# android-sample

A minimal Android app for verifying host builds and instrumentation tests. Pressing the button increments a counter; it has 2 Espresso instrumentation tests and 1 unit test.

```bash
./gradlew assembleDebug assembleDebugAndroidTest   # app/build/outputs/apk/debug/app-debug.apk, .../androidTest/debug/app-debug-androidTest.apk
```
On the platform, `DevSession.android_build()` sends this folder to the host as a snapshot, builds it there, and installs the resulting APK on the emulator.
