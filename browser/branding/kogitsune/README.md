# Kogitsune branding

The application package selects this directory for both normal and official
Kogitsune builds. `content/kogitsune-mascot.png` is the master app icon. The
PNG, ICO, and ICNS size variants are generated from it; the about-page SVGs
reference that same image so the browser UI and packaged application use one
consistent mark. GTK builds also package `kogitsune*.png` names because
Wayland window icon lookup uses the localized brand name rather than the
generic `default*.png` filenames.

The upstream `official`, `unofficial`, `aurora`, and `nightly` branding
directories remain unchanged in the source tree. They contain upstream Mozilla
branding and licensing material but are not selected by Kogitsune builds.

Kogitsune keeps the Firefox application ID for extension and upstream
integration compatibility. It uses its own executable and displayed product
name, vendor, macOS bundle ID, update channel, and profile directory.
The Mozilla Accounts logo remains on the Mozilla account connection flow
because it identifies that external service rather than the browser.
Mozilla service names such as Firefox Relay, Firefox Monitor, Firefox Suggest,
Firefox Screenshots, and Firefox Translations are retained where they identify
their respective Mozilla services. Browser-local features such as View, Home,
and Labs use Kogitsune names.

The Kogitsune update channel has no release service yet. Automatic update
requests are disabled, and manual update and release-note links point to the
project’s GitHub releases. Windows stub installers are not enabled for the
Kogitsune channel until a direct full-installer download and code-signing
identity are available.

Sponsored Pocket stories, sponsored New Tab shortcuts, and sponsored URL-bar
suggestions are disabled by default in Kogitsune builds.
