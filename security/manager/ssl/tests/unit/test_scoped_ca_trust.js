"use strict";

const SCOPED_CA_POLICY_PREF = "security.certificate_scoped_ca.policies";

add_task(async function testScopedCATrust() {
  do_get_profile();
  let certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(
    Ci.nsIX509CertDB
  );
  addCertFromFile(certDB, "bad_certs/test-ca.pem", "CTu,,");

  let ca = constructCertFromFile("bad_certs/test-ca.pem");
  let leaf = constructCertFromFile("bad_certs/default-ee.pem");
  let expiredLeaf = constructCertFromFile("bad_certs/expired-ee.pem");
  let fingerprint = ca.sha256Fingerprint.replace(/:/g, "").toLowerCase();
  let oldPolicies = Services.prefs.getStringPref(SCOPED_CA_POLICY_PREF, "");

  try {
    Services.prefs.setStringPref(
      SCOPED_CA_POLICY_PREF,
      `${fingerprint}=[^.]+\\.example\\.com\n${fingerprint}=api\\.test\\.example\\.com`
    );
    await checkCertErrorGeneric(
      certDB,
      leaf,
      PRErrorCodeSuccess,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      false,
      "service.example.com"
    );
    await checkCertErrorGeneric(
      certDB,
      expiredLeaf,
      SEC_ERROR_EXPIRED_CERTIFICATE,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      false,
      "expired.example.com"
    );
    await checkCertErrorGeneric(
      certDB,
      leaf,
      SEC_ERROR_UNTRUSTED_ISSUER,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      false,
      "localhost"
    );
    await checkCertErrorGeneric(
      certDB,
      expiredLeaf,
      SEC_ERROR_EXPIRED_CERTIFICATE,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      false,
      "expired.example.com"
    );
    await checkCertErrorGeneric(
      certDB,
      expiredLeaf,
      SSL_ERROR_BAD_CERT_DOMAIN,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      false,
      "wrong.example.com"
    );

    Services.prefs.setStringPref(
      SCOPED_CA_POLICY_PREF,
      `${fingerprint}=localhost`
    );
    await checkCertErrorGeneric(
      certDB,
      leaf,
      PRErrorCodeSuccess,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      false,
      "localhost"
    );
    await checkCertErrorGeneric(
      certDB,
      leaf,
      SEC_ERROR_UNTRUSTED_ISSUER,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      false,
      "service.example.com"
    );

    Services.prefs.setStringPref(SCOPED_CA_POLICY_PREF, `${fingerprint}=`);
    await checkCertErrorGeneric(
      certDB,
      leaf,
      SEC_ERROR_UNTRUSTED_ISSUER,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      false,
      "localhost"
    );

    Services.prefs.clearUserPref(SCOPED_CA_POLICY_PREF);
    await checkCertErrorGeneric(
      certDB,
      leaf,
      PRErrorCodeSuccess,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      false,
      "localhost"
    );
  } finally {
    if (oldPolicies) {
      Services.prefs.setStringPref(SCOPED_CA_POLICY_PREF, oldPolicies);
    } else {
      Services.prefs.clearUserPref(SCOPED_CA_POLICY_PREF);
    }
  }
});
