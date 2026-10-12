"use strict";

const { ScopedCACertFeed } = ChromeUtils.importESModule(
  "resource://gre/modules/psm/ScopedCACertFeed.sys.mjs"
);

add_task(function testScopedCAFeedManifestValidation() {
  let certificate = constructCertFromFile("bad_certs/test-ca.pem");
  let fingerprint = certificate.sha256Fingerprint
    .replace(/:/g, "")
    .toLowerCase();
  let certificatePEM = readFile(do_get_file("bad_certs/test-ca.pem", false));
  let manifest = {
    version: 1,
    certificateFingerprintSHA256: fingerprint,
    certificatePEM,
    hostnames: ["example.com", "api.example.com"],
    hostnamePatterns: ["(?:service|api)\\.example\\.com"],
  };

  let validated = ScopedCACertFeed.validateManifest(
    JSON.stringify(manifest),
    fingerprint
  );
  Assert.equal(validated.fingerprint, fingerprint);
  Assert.deepEqual(validated.hostnames, manifest.hostnames);
  Assert.deepEqual(validated.patterns, manifest.hostnamePatterns);
  Assert.deepEqual(validated.policyPatterns, [
    "example\\.com",
    "api\\.example\\.com",
    ...manifest.hostnamePatterns,
  ]);

  manifest.certificateFingerprintSHA256 = "0".repeat(64);
  Assert.throws(
    () =>
      ScopedCACertFeed.validateManifest(JSON.stringify(manifest), fingerprint),
    /fingerprint/
  );

  manifest.certificateFingerprintSHA256 = fingerprint;
  manifest.hostnames = ["*.example.com"];
  Assert.throws(
    () =>
      ScopedCACertFeed.validateManifest(JSON.stringify(manifest), fingerprint),
    /invalid allowed hostname/
  );
  manifest.hostnames = ["example.com"];
  manifest.hostnamePatterns = ["["];
  Assert.throws(
    () =>
      ScopedCACertFeed.validateManifest(JSON.stringify(manifest), fingerprint),
    /invalid hostname pattern/
  );
});
