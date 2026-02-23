# The MIT License
#
# Copyright 2022 Red Hat, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# for CertPathValidatorTests
set -ex
STORE=test.jks
PASSWD=password
KS="-keystore $STORE"
PS="-storepass $PASSWD"
KP="-keypass $PASSWD"
PSKS="$KS $PS"
ca=companythatdoesnotexist
chain1=intermediatecompanycertificate
chain2=thirdcompany
validity="-validity 36500"
alg="-keyalg RSA"

# clena legacy and new
rm -fv *.pem
keytool -list  $PSKS  ;
for  tcaw in  $ca  $chain1 $chain2 ca root server; do
  echo $tcaw ;
  keytool -delete -alias $tcaw  $PSKS || true
done
keytool -list  $PSKS  ;

# in original tutorial is bc:c
keytool -genkeypair $PSKS $KP $validity $alg -alias root -ext bc:ca:true -dname "ou=root, o=root, c=root"
keytool -genkeypair $PSKS $KP $validity $alg -alias ca -ext bc:ca:true -dname "ou=ca, o=ca, c=ca"
keytool -genkeypair $PSKS $KP $validity $alg -alias server -dname "cn=server, ou=server, o=server, c=server"

keytool $PSKS -alias root -exportcert -rfc > root.pem
keytool $PSKS -certreq -alias ca | keytool $PSKS -gencert $validity -alias root -ext BC=0 -rfc > ca.pem

cat root.pem ca.pem > cachain.pem
keytool $PSKS -importcert -alias ca -file cachain.pem

keytool $PSKS -certreq -alias server | keytool -$PSKS -gencert $validity -alias ca -ext ku:c=dig,keyEncipherment -rfc > server.pem
cat root.pem ca.pem server.pem > serverchain.pem
keytool $PSKS -importcert -alias server -file serverchain.pem

rm -fv *.pem
keytool -list -v $PSKS  ;

#see the difference between  test.jks.orig and this new one.  Here the server (thirdcomapny in orig) have chain length of FOUR (had just three)
