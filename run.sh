#!/bin/bash

###############################################################################################
# bash run.sh jdk [bug]
# bash run.sh jdk [dir]
# to run without jtreg (without this wrapper), your compilation and runtime on jdk11 and up, will need to be amended:
# javac -d $dir $clases   --add-reads java.base=ALL-UNNAMED       --add-exports  java.base/com.sun.crypto.provider=ALL-UNNAMED   --add-exports  java.base/sun.security.internal.spec=ALL-UNNAMED     --add-exports  java.base/sun.security.ssl=ALL-UNNAMED  --add-exports  java.base/sun.security.x509=ALL-UNNAMED   --add-reads java.security.jgss=ALL-UNNAMED --add-exports  java.security.jgss/sun.security.jgss=ALL-UNNAMED      --add-exports  java.security.jgss/sun.security.jgss.krb5=ALL-UNNAMED
# see also acompanying makefile
################################################################################################

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SCRIPT_SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  SCRIPT_DIR="$( cd -P "$( dirname "$SCRIPT_SOURCE" )" && pwd )"
  SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
  # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
  [[ $SCRIPT_SOURCE != /* ]] && SCRIPT_SOURCE="$SCRIPT_DIR/$SCRIPT_SOURCE"
done
readonly SCRIPT_DIR="$( cd -P "$( dirname "$SCRIPT_SOURCE" )" && pwd )"


envVarArg="-e:CUSTOM_DUMMY_VARIABLE=true,JAVA_TOOL_OPTIONS,OTOOL_BUILD_ARCH,DISPLAY"
keys=$(env | grep OTOOL_ | sed "s/=.*//")
for key in $keys; do
  envVarArg="$envVarArg,$key"
done

set -e
set -o pipefail

JAVA=${1}
if [ "x$JAVA" == "x" ] ; then 
  echo "Jdk is mandatory param (bugid is optional)"
  exit 1
fi;

if [ "x$JAVA_HOME" == "x" ] ; then 
  JAVA_HOME=$(dirname $(dirname $(readlink -f $(which javac))))
fi;

TIME=$(date +%s)
BUGID=${2}

FOLDER=${SCRIPT_DIR}
if [ "x$BUGID" != "x" -a -e "$BUGID" ] ; then
    FOLDER="$BUGID"
    BUGID=""
elif [ "x$BUGID" != "x" ]; then
  BUGID="-bug:$BUGID"
fi

if [ "x$JTREG_HOME" == "x" ] ; then
  JTREG_HOME="$SCRIPT_DIR/jtreg"
else
  if [ ! -e "$JTREG_HOME/lib/jtreg.jar" ] ; then
    echo "You have jtreg home set, but it do not contain lib/jtreg.jar"
    exit 1
  fi
fi

if [ ! -e "$JTREG_HOME" ] ; then
  ball=jtreg5.1-b01.tar.gz
  wget https://ci.adoptopenjdk.net/view/Dependencies/job/dependency_pipeline/lastSuccessfulBuild/artifact/jtreg/$ball
  tar -xf $ball
fi

AGENT_OPT=""
if [ -n "${SKIP_AGENT_TESTS:-}" ] ; then
    AGENT_OPT="-javaoption:-Dcryptotests.skipAgentTests=1"
fi

echo Running with $JAVA...

r=0
mkdir -p test.${TIME}/jdk/JTwork test.${TIME}/jdk/JTreport
${JAVA_HOME}/bin/java -jar $JTREG_HOME/lib/jtreg.jar -v1 -a -ignore:quiet \
		-w:test.${TIME}/jdk/JTwork -r:test.${TIME}/jdk/JTreport \
		-jdk:$JAVA \
		-xml \
		$BUGID \
		$AGENT_OPT \
                $envVarArg \
		$FOLDER \
	    | tee test.${TIME}/tests.log || r=$?

tar -czf test.${TIME}.tar.gz test.${TIME}/jdk/JTwork test.${TIME}/jdk/JTreport

if ! [ -f test.${TIME}/tests.log ] ; then
	echo "Missing tests.log!" 1>&2
	exit 1
fi
# passes should be present in tests.log
grep -Eqi '^passed:' test.${TIME}/tests.log || exit 1
# check for failures/errors in tests.log 
! grep -Eqi '^(failed|error):' test.${TIME}/tests.log || exit 1

exit $r
