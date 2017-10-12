# CryptoTest
Complete example of java crypto API

This "test" is able to iterate through all algorithms (even aliases) which all java crypto providers provides.
Every algorithm is initialised, and used. This is probably hugest collection of usages of java crypto api. I'm  afraid some of the apis were nto used in last 10 years anywhere else.

Current covered jdk is java8. With few exceptions it wil work in jdk9 to.
The entry pooint is cryptotest.CryptoTest. You can lunch individual providers as main methods too.

In jdk9, you need to add minimu of:
 --add-reads java.base=ALL-UNNAMED  --add-exports  java.base/com.sun.crypto.provider=ALL-UNNAMED   --add-exports  java.base/sun.security.internal.spec=ALL-UNNAMED     --add-exports  java.base/sun.security.ssl=ALL-UNNAMED  --add-exports  java.base/sun.security.x509=ALL-UNNAMED   --add-reads java.security.jgss=ALL-UNNAMED --add-exports  java.security.jgss/sun.security.jgss=ALL-UNNAMED      --add-exports  java.security.jgss/sun.security.jgss.krb5=ALL-UNNAMED 
 for both java and javac, and I'm not usre if:
    rm ./cryptotest/tests/CertPathBuilderTests.java
    rm ./cryptotest/tests/TerminalFactoryTests.java
  can be fixed. On contary:
    rm ./cryptotest/tests/GssApiMechanismTests.java
    rm ./cryptotest/tests/KeyAgreementTests.java
    rm ./cryptotest/tests/KeyInfoFactoryTests.java
 Can be fixed, and I was just lazy.
 
 This project would never be created without extensive help of
    sparkoo@github
    oklinov@github
    mzezulka@redhat
    pmikova@redhat
 
 
