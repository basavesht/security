#!/bin/bash

# ***********************************************************************
# This batch file for Running encryption util.
# ***********************************************************************

export JAVA_HOME=$JAVA_HOME
export PATH=$PATH:$JAVA_HOME/bin
echo "********** Running the following commands **********"
echo "PATH : $PATH"
echo "java -jar hbs-db-encrypt-util.jar &"
java -jar hbs-db-encrypt-util.jar
# END of the file