/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

const FEED_URL =
  "https://raw.githubusercontent.com/kogitsune-browser/sitelist/main/sitelist.json";
const CERTIFICATE_FINGERPRINT =
  "aa7ff637d061295a6a003e9d6621a54f4780bae7aef96043a71b7c2af276d556";
const ENABLED_PREF = "security.certificate_scoped_ca.github_feed.enabled";
const LAST_UPDATE_PREF =
  "security.certificate_scoped_ca.github_feed.last_update";
const INITIALIZED_PREF =
  "security.certificate_scoped_ca.github_feed.initialized";
const POLICIES_PREF = "security.certificate_scoped_ca.policies";
const REFRESH_INTERVAL = 24 * 60 * 60 * 1000;
const MAX_FEED_SIZE = 64 * 1024;
const MAX_PATTERN_COUNT = 64;
const MAX_HOSTNAME_COUNT = 256;
const BOOTSTRAP_RETRY_INTERVAL = 60 * 60 * 1000;

const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(
  Ci.nsIX509CertDB
);
let refreshTimer;
let bootstrapRetryTimer;

function normalizeFingerprint(fingerprint) {
  return fingerprint.replaceAll(":", "").toLowerCase();
}

function parseManifest(text, expectedFingerprint = CERTIFICATE_FINGERPRINT) {
  expectedFingerprint = normalizeFingerprint(expectedFingerprint);
  if (new TextEncoder().encode(text).byteLength > MAX_FEED_SIZE) {
    throw new Error("The GitHub feed is too large");
  }

  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch {
    throw new Error("The GitHub feed is not valid JSON");
  }

  if (
    manifest.version !== 1 ||
    (!Array.isArray(manifest.hostnames) &&
      !Array.isArray(manifest.hostnamePatterns)) ||
    (manifest.hostnames ?? []).length +
      (manifest.hostnamePatterns ?? []).length ===
      0 ||
    (manifest.hostnames ?? []).length > MAX_HOSTNAME_COUNT ||
    (manifest.hostnamePatterns ?? []).length > MAX_PATTERN_COUNT
  ) {
    throw new Error("The GitHub feed has an unsupported format");
  }
  if (
    normalizeFingerprint(manifest.certificateFingerprintSHA256 ?? "") !==
    expectedFingerprint
  ) {
    throw new Error("The GitHub feed fingerprint does not match");
  }

  for (const hostname of manifest.hostnames ?? []) {
    if (
      typeof hostname !== "string" ||
      hostname.length > 253 ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(
        hostname
      )
    ) {
      throw new Error("The GitHub feed contains an invalid allowed hostname");
    }
  }

  for (const pattern of manifest.hostnamePatterns ?? []) {
    if (
      typeof pattern !== "string" ||
      !pattern ||
      pattern.length > 256 ||
      /[\r\n]/.test(pattern)
    ) {
      throw new Error("The GitHub feed contains an invalid hostname pattern");
    }
    try {
      new RegExp(pattern);
    } catch {
      throw new Error("The GitHub feed contains an invalid hostname pattern");
    }
  }

  let pem = manifest.certificatePEM;
  let match =
    typeof pem === "string" &&
    pem.match(
      /^-----BEGIN CERTIFICATE-----\s*([\s\S]+?)\s*-----END CERTIFICATE-----\s*$/
    );
  if (!match || pem.indexOf("-----BEGIN CERTIFICATE-----", 1) !== -1) {
    throw new Error("The GitHub feed does not contain one PEM certificate");
  }

  let certificateBase64 = match[1].replace(/\s/g, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(certificateBase64)) {
    throw new Error("The GitHub feed certificate is not valid base64");
  }

  let certificate;
  try {
    certificate = certDB.constructX509FromBase64(certificateBase64);
  } catch {
    throw new Error("The GitHub feed certificate could not be parsed");
  }

  if (
    normalizeFingerprint(certificate.sha256Fingerprint) !== expectedFingerprint
  ) {
    throw new Error("The GitHub feed certificate fingerprint does not match");
  }

  return {
    text,
    certificate,
    certificateBase64,
    fingerprint: expectedFingerprint,
    hostnames: manifest.hostnames ?? [],
    patterns: manifest.hostnamePatterns ?? [],
    policyPatterns: [
      ...(manifest.hostnames ?? []).map(hostname =>
        hostname.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
      ),
      ...(manifest.hostnamePatterns ?? []),
    ],
  };
}

async function fetchManifest() {
  if (Cu.isInAutomation) {
    throw new Error("GitHub downloads are disabled during browser automation");
  }
  let response = await fetch(FEED_URL, {
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
  if (!response.ok) {
    throw new Error(`GitHub returned HTTP ${response.status}`);
  }
  let contentLength = Number(response.headers.get("content-length"));
  if (contentLength > MAX_FEED_SIZE) {
    throw new Error("The GitHub feed is too large");
  }

  let reader = response.body.getReader();
  let chunks = [];
  let total = 0;
  for (;;) {
    let { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.length;
    if (total > MAX_FEED_SIZE) {
      await reader.cancel();
      throw new Error("The GitHub feed is too large");
    }
    chunks.push(value);
  }

  let bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  let text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return parseManifest(text);
}

function cacheManifest(text) {
  let directory = Services.dirsvc.get("ProfD", Ci.nsIFile);
  directory.append("security");
  if (!directory.exists()) {
    directory.create(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
  }
  let file = directory.clone();
  file.append("kogitsune-sitelist.json");
  let output = Cc["@mozilla.org/network/file-output-stream;1"].createInstance(
    Ci.nsIFileOutputStream
  );
  output.init(file, 0x02 | 0x08 | 0x20, 0o600, 0);
  let converter = Cc[
    "@mozilla.org/intl/converter-output-stream;1"
  ].createInstance(Ci.nsIConverterOutputStream);
  converter.init(output, "UTF-8", 0, 0);
  converter.writeString(text);
  converter.close();
}

function savePatterns(feed) {
  let policies = Services.prefs
    .getStringPref(POLICIES_PREF, "")
    .split(/\r?\n/)
    .filter(Boolean)
    .filter(entry => !entry.toLowerCase().startsWith(`${feed.fingerprint}=`));
  policies.push(
    ...feed.policyPatterns.map(pattern => `${feed.fingerprint}=${pattern}`)
  );
  Services.prefs.setStringPref(POLICIES_PREF, policies.join("\n"));
}

async function findInstalledCertificate(fingerprint) {
  let certificates = await certDB.getCerts();
  return certificates.find(
    certificate =>
      normalizeFingerprint(certificate.sha256Fingerprint) === fingerprint
  );
}

async function addCertificateWithoutGeneralTrust(feed) {
  let existing = await findInstalledCertificate(feed.fingerprint);
  if (existing) {
    let emailTrust = certDB.isCertTrusted(
      existing,
      Ci.nsIX509Cert.CA_CERT,
      Ci.nsIX509CertDB.TRUSTED_EMAIL
    )
      ? Ci.nsIX509CertDB.TRUSTED_EMAIL
      : 0;
    certDB.setCertTrust(existing, Ci.nsIX509Cert.CA_CERT, emailTrust);
    return;
  }

  certDB.addCertFromBase64(feed.certificateBase64, ",,");
}

async function applyFeed(feed, automaticRefresh) {
  await cacheManifest(feed.text);
  await addCertificateWithoutGeneralTrust(feed);
  savePatterns(feed);
  Services.prefs.setBoolPref(ENABLED_PREF, automaticRefresh);
  Services.prefs.setBoolPref(INITIALIZED_PREF, true);
  Services.prefs.setStringPref(LAST_UPDATE_PREF, String(Date.now()));
  if (automaticRefresh) {
    startTimer();
  }
}

async function refreshIfDue(force = false) {
  if (!Services.prefs.getBoolPref(ENABLED_PREF, false)) {
    return;
  }

  let lastUpdate = Number(Services.prefs.getStringPref(LAST_UPDATE_PREF, "0"));
  if (!force && Date.now() - lastUpdate < REFRESH_INTERVAL) {
    return;
  }

  let feed = await fetchManifest();
  if (!(await findInstalledCertificate(feed.fingerprint))) {
    Services.prefs.setBoolPref(ENABLED_PREF, false);
    Services.prefs.setStringPref(
      POLICIES_PREF,
      Services.prefs
        .getStringPref(POLICIES_PREF, "")
        .split(/\r?\n/)
        .filter(
          entry =>
            entry && !entry.toLowerCase().startsWith(`${feed.fingerprint}=`)
        )
        .join("\n")
    );
    return;
  }

  await cacheManifest(feed.text);
  savePatterns(feed);
  Services.prefs.setStringPref(LAST_UPDATE_PREF, String(Date.now()));
}

function startTimer() {
  if (refreshTimer) {
    return;
  }
  refreshTimer = Cc["@mozilla.org/timer;1"].createInstance(Ci.nsITimer);
  refreshTimer.initWithCallback(
    {
      notify() {
        refreshIfDue(true).catch(error =>
          console.error("Could not refresh the Kogitsune CA sitelist", error)
        );
      },
    },
    REFRESH_INTERVAL,
    Ci.nsITimer.TYPE_REPEATING_SLACK
  );
}

function scheduleBootstrapRetry() {
  if (bootstrapRetryTimer) {
    return;
  }
  bootstrapRetryTimer = Cc["@mozilla.org/timer;1"].createInstance(Ci.nsITimer);
  bootstrapRetryTimer.initWithCallback(
    {
      notify() {
        bootstrapRetryTimer = null;
        ScopedCACertFeed.startup();
      },
    },
    BOOTSTRAP_RETRY_INTERVAL,
    Ci.nsITimer.TYPE_ONE_SHOT
  );
}

export var ScopedCACertFeed = {
  validateManifest(text, expectedFingerprint) {
    return parseManifest(text, expectedFingerprint);
  },

  async preview() {
    let feed = await fetchManifest();
    return {
      commonName: feed.certificate.commonName,
      fingerprint: feed.fingerprint,
      hostnames: feed.hostnames,
      patterns: feed.patterns,
      text: feed.text,
    };
  },

  async getScopedStatus() {
    let entries = Services.prefs
      .getStringPref(POLICIES_PREF, "")
      .split(/\r?\n/)
      .filter(Boolean);
    let certificates = await certDB.getCerts();
    let installedFingerprints = new Set(
      certificates.map(certificate =>
        normalizeFingerprint(certificate.sha256Fingerprint)
      )
    );
    let activePolicies = entries.filter(entry => {
      let separator = entry.indexOf("=");
      return (
        separator === 64 &&
        installedFingerprints.has(
          normalizeFingerprint(entry.slice(0, separator))
        )
      );
    });
    return {
      certificateCount: new Set(
        activePolicies.map(entry => entry.slice(0, 64).toLowerCase())
      ).size,
      domainCount: activePolicies.length,
    };
  },

  async install(feed, automaticRefresh) {
    let validated = parseManifest(feed.text);
    await applyFeed(validated, automaticRefresh);
  },

  isSubscribed(fingerprint) {
    return (
      normalizeFingerprint(fingerprint) === CERTIFICATE_FINGERPRINT &&
      Services.prefs.getBoolPref(ENABLED_PREF, false)
    );
  },

  unsubscribe(fingerprint) {
    if (normalizeFingerprint(fingerprint) === CERTIFICATE_FINGERPRINT) {
      Services.prefs.setBoolPref(ENABLED_PREF, false);
      Services.prefs.setBoolPref(INITIALIZED_PREF, true);
    }
  },

  async startup() {
    if (Cu.isInAutomation) {
      return;
    }
    if (!Services.prefs.getBoolPref(INITIALIZED_PREF, false)) {
      if (await findInstalledCertificate(CERTIFICATE_FINGERPRINT)) {
        Services.prefs.setBoolPref(INITIALIZED_PREF, true);
        return;
      }
      try {
        await applyFeed(await fetchManifest(), true);
      } catch (error) {
        console.error("Could not install the Kogitsune CA sitelist", error);
        scheduleBootstrapRetry();
      }
      return;
    }

    if (!Services.prefs.getBoolPref(ENABLED_PREF, false)) {
      return;
    }
    try {
      await refreshIfDue();
    } catch (error) {
      console.error("Could not refresh the Kogitsune CA sitelist", error);
    }

    startTimer();
  },
};
