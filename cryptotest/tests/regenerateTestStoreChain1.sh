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
validity="-validity 2000"

# clena legacy and new
rm -fv *.pem
keytool -list  $PSKS  ;
for  tcaw in  $ca  $chain1 $chain2 ca root server; do
  echo $tcaw ;
  keytool -delete -alias $tcaw  $PSKS || true
done
keytool -list  $PSKS  ;

# in original tutorial is bc:c
keytool -genkeypair $PSKS $KP $validity -alias root -ext bc:ca:true -dname "ou=root, o=root, c=root"
keytool -genkeypair $PSKS $KP $validity -alias ca -ext bc:ca:true -dname "ou=ca, o=ca, c=ca"
keytool -genkeypair $PSKS $KP $validity -alias server -dname "cn=server, ou=server, o=server, c=server"

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
