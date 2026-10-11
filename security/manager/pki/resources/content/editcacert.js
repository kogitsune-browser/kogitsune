/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var gCertDB = Cc["@mozilla.org/security/x509certdb;1"].getService(
  Ci.nsIX509CertDB
);
/**
 * Cert to edit the trust of.
 *
 * @type {nsIX509Cert}
 */
var gCert = window.arguments[0];
const SCOPED_CA_POLICY_PREF = "security.certificate_scoped_ca.policies";

document.addEventListener("DOMContentLoaded", init);

function init() {
  document.addEventListener("dialogaccept", onDialogAccept);

  let sslCheckbox = document.getElementById("trustSSL");
  sslCheckbox.checked = gCertDB.isCertTrusted(
    gCert,
    Ci.nsIX509Cert.CA_CERT,
    Ci.nsIX509CertDB.TRUSTED_SSL
  );

  let emailCheckbox = document.getElementById("trustEmail");
  emailCheckbox.checked = gCertDB.isCertTrusted(
    gCert,
    Ci.nsIX509Cert.CA_CERT,
    Ci.nsIX509CertDB.TRUSTED_EMAIL
  );

  let certMsg = document.getElementById("certmsg");
  document.l10n.setAttributes(certMsg, "edit-trust-ca", {
    certName: gCert.commonName,
  });

  let fingerprint = getCertFingerprint();
  let patterns = getScopedCAPolicies()
    .filter(entry => entry.toLowerCase().startsWith(`${fingerprint}=`))
    .map(entry => entry.slice(fingerprint.length + 1));
  let scopedTrust = document.getElementById("scopedTrust");
  let scopedDomains = document.getElementById("scopedDomains");
  scopedTrust.checked = patterns.length > 0;
  scopedDomains.value = patterns.join("\n");
  updateScopedTrustControls();
  scopedTrust.addEventListener("command", updateScopedTrustControls);
}

/**
 * ondialogaccept() handler.
 */
function onDialogAccept(event) {
  let sslCheckbox = document.getElementById("trustSSL");
  let emailCheckbox = document.getElementById("trustEmail");
  let trustSSL = sslCheckbox.checked ? Ci.nsIX509CertDB.TRUSTED_SSL : 0;
  let trustEmail = emailCheckbox.checked ? Ci.nsIX509CertDB.TRUSTED_EMAIL : 0;

  let domains = [];
  if (document.getElementById("scopedTrust").checked) {
    domains = document
      .getElementById("scopedDomains")
      .value.split(/\r?\n/)
      .map(domain => domain.trim())
      .filter(Boolean);
    if (
      !domains.length ||
      domains.some(pattern => !isValidScopedPattern(pattern))
    ) {
      event.preventDefault();
      document.l10n
        .formatValue("certmgr-edit-cert-scoped-domains-invalid")
        .then(message => window.alert(message));
      return;
    }
  }

  gCertDB.setCertTrust(gCert, Ci.nsIX509Cert.CA_CERT, trustSSL | trustEmail);
  saveScopedCAPolicy(domains);
}

function updateScopedTrustControls() {
  let scopedTrust = document.getElementById("scopedTrust").checked;
  let sslCheckbox = document.getElementById("trustSSL");
  let domainsTextbox = document.getElementById("scopedDomains");
  if (scopedTrust) {
    sslCheckbox.checked = false;
  }
  sslCheckbox.disabled = scopedTrust;
  domainsTextbox.disabled = !scopedTrust;
}

function getCertFingerprint() {
  return gCert.sha256Fingerprint.replace(/:/g, "").toLowerCase();
}

function getScopedCAPolicies() {
  return Services.prefs
    .getStringPref(SCOPED_CA_POLICY_PREF, "")
    .split(/\r?\n/)
    .filter(Boolean);
}

function saveScopedCAPolicy(domains) {
  let fingerprint = getCertFingerprint();
  let policies = getScopedCAPolicies().filter(
    policy => !policy.toLowerCase().startsWith(`${fingerprint}=`)
  );
  policies.push(...domains.map(pattern => `${fingerprint}=${pattern}`));
  Services.prefs.setStringPref(SCOPED_CA_POLICY_PREF, policies.join("\n"));
}

function isValidScopedPattern(pattern) {
  if (!pattern || pattern.length > 256) {
    return false;
  }
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}
