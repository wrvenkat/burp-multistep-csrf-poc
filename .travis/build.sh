#!/bin/bash

# Build MultiStepCSRFPOC.jar
# Maven couldn't be used because the getProtocol() appears to be deprecated and is located only when the Burp suite's jar is used as part of the build.

JYTHON_URL="https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.1/jython-standalone-2.7.1.jar"
BURP_SUITE_URL="https://portswigger.net/burp/releases/download?product=community&version=1.7.36&type=jar"

FUTURE_URL="https://files.pythonhosted.org/packages/90/52/e20466b85000a181e1e144fd8305caf2cf475e2f9674e797b222f8105f5f/future-0.17.1.tar.gz"
SIX_URL="https://files.pythonhosted.org/packages/dd/bf/4138e7bfb757de47d1f4b6994648ec67a51efe58fa907c1e11e350cddfca/six-1.12.0.tar.gz"

REQUEST_PARSER_URL="https://github.com/wrvenkat/request_parser.git"
REQUEST_GENERATOR_URL="https://github.com/wrvenkat/request_generator.git"

WORKING_DIR=~/build/wrvenkat/burp-multistep-csrf-poc
DEPENDENCY_DIR="lib"
BUILD_DIR="build"
DIST_DIR="dist"
MODULE_DIR="module"

java -version

# remove dirs
printf "Cleaning up...\n"
rm -rf "$DEPENDENCY_DIR"
rm -rf "$BUILD_DIR"
rm -rf "$DIST_DIR"
rm -rf "$MODULE_DIR"

# make necessary directories
printf "Creating build, dependency and module directories...\n" &&\
mkdir "$DEPENDENCY_DIR" &&\
mkdir "$BUILD_DIR" &&\
mkdir "$DIST_DIR" &&\
mkdir "$MODULE_DIR" &&\

# download Jython and Burp suite into lib folder
printf "Downloading Java depedencies...\n" &&\
wget -O $DEPENDENCY_DIR/jython.jar "$JYTHON_URL" &&\
wget -O $DEPENDENCY_DIR/burpsuite.jar "$BURP_SUITE_URL" &&\

# build the src
printf "Compiling Java sources...\n"
javac $(find src/ -name "*.java") -classpath lib/jython.jar:lib/burpsuite.jar -d $BUILD_DIR &&\

# copy the python part too
cp -r src/parserbuilder/python $BUILD_DIR/parserbuilder/ &&\
cp src/parserbuilder/__init__.py $BUILD_DIR/parserbuilder/ &&\

# download python modules to build directory
wget -O $MODULE_DIR/future.tar.gz "$FUTURE_URL" &&\
wget -O $MODULE_DIR/six.tar.gz "$SIX_URL" &&\

#extract and move 3rd party modules
printf "Adding python modules...\n"
cd $MODULE_DIR
mkdir future &&\
mkdir six &&\
tar -xvzf future.tar.gz -C future --strip-components 1 &&\
tar -xvzf six.tar.gz -C six --strip-components 1 &&\
mv future/src/future/ ../$BUILD_DIR &&\
mv six/six.py ../$BUILD_DIR &&\

#checkout the 1st part modules
git clone "$REQUEST_PARSER_URL" &&\
git clone "$REQUEST_GENERATOR_URL" &&\
cd request_parser && for f in $(find . -name 'tests'); do rm -rf "$f"; done && cd .. &&\
cd request_generator && for f in $(find . -name 'tests'); do rm -rf "$f"; done && cd .. &&\
cp -r request_parser/request_parser/ ../$BUILD_DIR &&\
cp -r request_generator/request_generator/ ../$BUILD_DIR &&\
cd .. && ls -l

#build jar file
printf "Building JAR package...\n"
version=$(git tag --sort=committerdate | tail -n1) &&\
cd $BUILD_DIR &&\
jar cvf ../$DIST_DIR/MultiStepCSRFPOC-"$version".jar * &&\
cd ..
