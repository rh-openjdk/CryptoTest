JAVA ?= $(shell if [ -n "$(JAVA_HOME)" ] ; then printf '%s/bin/java' "$(JAVA_HOME)" ; else printf 'java' ; fi )
JAVAC ?= $(shell if [ -n "$(JAVA_HOME)" ] ; then printf '%s/bin/javac' "$(JAVA_HOME)" ; else printf 'javac' ; fi )

JAVA_VERSION_MAJOR := $(shell "$(JAVA)" -version 2>&1 | grep version | head -n 1 | sed -E 's/^.*"(1[.])?([0-9]+).*$$/\2/g' )

MOD_ARGS := $(shell [ $(JAVA_VERSION_MAJOR) -gt 8 ] && printf '%s' ' --add-reads java.base=ALL-UNNAMED --add-exports java.base/com.sun.crypto.provider=ALL-UNNAMED --add-exports java.base/sun.security.internal.spec=ALL-UNNAMED --add-exports  java.base/sun.security.ssl=ALL-UNNAMED  --add-exports  java.base/sun.security.x509=ALL-UNNAMED --add-reads java.security.jgss=ALL-UNNAMED --add-exports java.security.jgss/sun.security.jgss=ALL-UNNAMED --add-exports java.security.jgss/sun.security.jgss.krb5=ALL-UNNAMED --add-exports java.security.jgss/sun.security.krb5=ALL-UNNAMED --add-reads java.xml.crypto=ALL-UNNAMED --add-exports java.xml.crypto/org.jcp.xml.dsig.internal.dom=ALL-UNNAMED --add-modules=jdk.crypto.ec --add-reads jdk.crypto.ec=ALL-UNNAMED --add-exports jdk.crypto.ec/sun.security.ec=ALL-UNNAMED --add-opens java.base/java.security=ALL-UNNAMED ' )
JAVA_MOD_ARGS := $(MOD_ARGS)
JAVAC_MOD_ARGS := $(shell [ $(JAVA_VERSION_MAJOR) -le 8 ] && printf '%s' '-XDignore.symbol.file=true ' ; printf '%s' "$(MOD_ARGS)" )

# to allow exclude tests for some jdk
TESTS_EXCLUDE := $(shell printf '%s' ".*[.]sh" ;  )

SKIP_AGENT_TESTS_ARG := $(shell [ 1 = "$(SKIP_AGENT_TESTS)" ] && printf '%s' '-Dcryptotests.skipAgentTests=1' )

TEST_NAMES := $(patsubst cryptotest/tests/%Tests.java,%Tests,$(wildcard cryptotest/tests/*Tests.java))

.PHONY: clean CryptoTest all list-tests $(TEST_NAMES)

all: CryptoTest

clean:
	rm -rf classes

classes:
	mkdir -p classes
	$(JAVAC) $(JAVAC_MOD_ARGS)  -d classes $(shell find cryptotest -name '*.java' | grep -v -E "$(TESTS_EXCLUDE)" )
	cp cryptotest/tests/test.jks classes/cryptotest/tests

CryptoTest: | classes
	$(JAVA) $(JAVA_MOD_ARGS) -cp classes $(SKIP_AGENT_TESTS_ARG) cryptotest.CryptoTest

list-tests:
	@printf '%s\n' $(TEST_NAMES) | tr ' ' '\n' | sort

$(TEST_NAMES): | classes
	$(JAVA) $(JAVA_MOD_ARGS) -cp classes $(SKIP_AGENT_TESTS_ARG) cryptotest.tests.$@
