# Client-side technology that is no longer supported (9 October 2026)


ASVS V3.7.1 asks that the app uses only client-side technology that is still supported (ADR-070).
`config.client-tech-unsupported`, in `crates/sv-check/src/client_tech.rs`, looks for two kinds. The first is the
retired browser plug-ins the requirement names: a `.swf` or `.xap` among the app's files, and in its pages, templates
and components `<applet`, an `<object>` with a `clsid:` class, the Flash and Silverlight content types, an `<embed>` of
a `.swf`, and `language="vbscript"`. `ActiveXObject` alone is not counted, since old libraries name it as a fallback.

The second is front-end libraries past their end of life, with the dates read from endoflife.date on 9 October 2026:
AngularJS (the package `angular`, every version), Vue 2 or older, Bootstrap 4 or older, and jQuery 1 or 2. They are
found in three places: the bill of materials, which holds what a lockfile says is installed; what a `package.json`
asks for, when there is no lockfile; and an address that loads one from a CDN with its version in it. Each finding
names the library and when its support ended. A name must follow `/`, `@` or `-` and be followed by its version, so
`myvue@2` is not Vue and `@angular/core@18` is not AngularJS. It is only ever a finding (medium): no list of what a
page loads is complete.

Checked: four tests, with every library and plug-in found, AngularJS under each name a CDN gives it, a version only the
lockfile names, and supported versions and look-alikes left alone. Eight breaks, one at a time. Two were caught only
once cases were added: the `angular.js` alias, and the rule that a name must follow `/`, `@` or `-`. The first version
read only the bill of materials, which lists nothing for a `package.json` with no lockfile; its own test showed that,
and what a `package.json` asks for is read too now.
