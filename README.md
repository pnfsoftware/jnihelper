# JNI Detection Plugin for JEB

This plugin helps analyze Android apps using native code and the Java Native Interfaces (JNI).

## How to use

Tutorial: https://www.pnfsoftware.com/blog/dynamic-jni-detection-plugin/

## Customizing and building

A build of this plugin ships with all distributions of JEB.

However, if you wish to customize this plugin (eg, modify or add your own heuristics):
- Clone the repository
- Define your JEB_HOME environment variable
- Optional: if you wish to work using the Eclipse IDE:
  - Create your Eclipse project by running create-eclipse-project-windows.cmd or create-eclipse-project-linux.sh
  - Import the project into Eclipse
- Build your plugin by running build-windows.cmd or build-linux.sh
  - Make sure to update the version numbers in the build scripts to reflect the version number in DynamicJNIDetectionPlugin.java
- The output plugin (jar file) goes to out/
- Copy the plugin to your JEB/coreplugins/ folder

Feel free to share your improvements by submitting a PR.