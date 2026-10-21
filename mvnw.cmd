@REM Maven Wrapper Script for Windows
@SETLOCAL

@SET JAVA_HOME=C:\Program Files\Java\jdk-24
@SET JAVA_EXE=%JAVA_HOME%\bin\java.exe
@SET MAVEN_PROJECTBASEDIR=%~dp0
@SET WRAPPER_JAR=%MAVEN_PROJECTBASEDIR%.mvn\wrapper\maven-wrapper.jar

@"%JAVA_EXE%" --add-opens=java.base/java.lang=ALL-UNNAMED --enable-native-access=ALL-UNNAMED -classpath "%WRAPPER_JAR%" "-Dmaven.multiModuleProjectDirectory=%MAVEN_PROJECTBASEDIR%" org.apache.maven.wrapper.MavenWrapperMain %*

@IF ERRORLEVEL 1 EXIT /B 1
@EXIT /B 0
