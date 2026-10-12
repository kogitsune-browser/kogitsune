/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  let { feed } = window.arguments[0];
  document.l10n.setAttributes(
    document.getElementById("scopedFeedCertificate"),
    "certmgr-scoped-feed-certificate",
    { certName: feed.commonName }
  );
  document.l10n.setAttributes(
    document.getElementById("scopedFeedFingerprint"),
    "certmgr-scoped-feed-fingerprint",
    { fingerprint: feed.fingerprint }
  );
  document.getElementById("scopedFeedHostnames").value =
    feed.hostnames.join("\n");
  document.getElementById("scopedFeedPatterns").value =
    feed.patterns.join("\n");
  document.addEventListener("dialogaccept", () => {
    window.arguments[0].accepted = true;
    window.arguments[0].automaticRefresh = document.getElementById(
      "scopedFeedAutomaticRefresh"
    ).checked;
  });
});
