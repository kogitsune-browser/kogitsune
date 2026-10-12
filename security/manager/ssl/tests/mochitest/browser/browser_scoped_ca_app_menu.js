/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";
/* global PanelUI */

add_task(async function test_scoped_ca_app_menu() {
  let mainViewShown = BrowserTestUtils.waitForEvent(PanelUI.panel, "ViewShown");
  PanelUI.show();
  await mainViewShown;

  let trustButton = document.getElementById("appMenu-scoped-ca-trust-button");
  Assert.ok(trustButton, "The app menu exposes scoped CA trust");

  let trustViewShown = BrowserTestUtils.waitForEvent(PanelUI.panel, "ViewShown");
  trustButton.click();
  let event = await trustViewShown;
  Assert.equal(
    event.originalTarget.id,
    "appMenu-scoped-ca-trust-view",
    "The scoped CA trust view opens"
  );

  let status = document.getElementById("appMenu-scoped-ca-trust-status");
  await TestUtils.waitForCondition(() =>
    status.hasAttribute("data-l10n-id")
  );
  Assert.equal(
    status.getAttribute("data-l10n-id"),
    "appmenu-scoped-ca-trust-status",
    "The status row is localized"
  );

  let managerPromise = BrowserTestUtils.domWindowOpenedAndLoaded();
  document.getElementById("appMenu-scoped-ca-manage-button").click();
  let manager = await managerPromise;
  Assert.equal(
    manager.document.documentURI,
    "chrome://pippki/content/certManager.xhtml",
    "The app menu opens certificate management"
  );

  manager.document.getElementById("certmanager").acceptDialog();
  await BrowserTestUtils.windowClosed(manager);

  PanelUI.hide();
});
