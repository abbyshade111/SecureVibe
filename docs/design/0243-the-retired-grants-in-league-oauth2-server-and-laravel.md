# The retired grants in league/oauth2-server and Laravel Passport (7 October 2026)

`config.retired-grant-enabled` (V10.4.4) reads an app's own sign-in server code for the password and implicit
grants switched on. It knew four libraries. league/oauth2-server, the one PHP library the proposal named, was left
out because its source could not be fetched then. It was read on 7 October 2026, with Laravel Passport 13, which most
PHP apps reach it through:

- **league/oauth2-server:** a grant is switched on by handing an instance to
  `AuthorizationServer::enableGrantType`, and the two retired ones are `Grant\PasswordGrant` and
  `Grant\ImplicitGrant`. So `new PasswordGrant(` and `new ImplicitGrant(` are what is looked for, imported or
  written in full with or without a leading backslash.
- **Laravel Passport:** it builds league's server itself and switches the two on only after
  `Passport::enablePasswordGrant()` or `Passport::enableImplicitGrant()`, the calls its documentation puts in a
  service provider's `boot`.

As for the others:
- A file is read when it names the library (`League\OAuth2\Server`, `Laravel\Passport`) or when the library is
  among the app's packages. So a Passport call made through Laravel's short alias is found where `composer.lock` lists
  Passport.
- A line that is only a comment is not read.
- It is only ever a finding.

Not seen: Passport before version 12, which had the password grant on with no switch to find.

Broken on purpose 9 ways, each caught:
- either switch never matched;
- the leading backslash not allowed;
- the namespace written in full not allowed;
- league's marker wrong, and made to match anything (which an app's own class named `PasswordGrant` then catches);
- Passport's marker, package name, and package ecosystem each wrong.
