# Changelog

### 0.0.5 - Sunday 27th September, 2026

- Updated dependencies

### 0.0.4 - Monday 14th September, 2026

- Updated package-lock.json file

### 0.0.3 - Monday 14th September, 2026

- Add hooks.onSignup and export createAuthenticateSession
- Fix Postgres bug where lockout bookkeeping silently broke after the first failed attempt
- Own password verification and rate limiting instead of delegating to User.authenticate()
- Fix type/model bugs found by a real dogfood app

### 0.0.2 - Thursday 3rd September, 2026

- Warn against combining sessions + mfa-sms in the README
- Add e2e coverage for magicLink-only and magicLink+totp wizard recipes
- Add mfa-sms as a wizard option
- Fix update-changelog script for a repo with no release tags yet
- Add GitHub Actions CI workflow and README badge
- Add Dependabot config for npm version updates
- Fix Dependabot alert: bump fastify to 5.12.1 (X-Forwarded-* spoofing)
- Make mobile_number genuinely optional in mfa-totp and sessions signup
- Add an interactive CLI wizard for composing custom auth flows
- Restructure strategies into composable building blocks in src/core/
- Fix ERR_PACKAGE_PATH_NOT_EXPORTED for the middleware/authenticate subpath
- Documented the updatePassword requirement on IUserModel
- Added a FAQs section covering combining sessions + magic-links strategies
- Fleshed out the README with request/response examples
- Unit tests for the app_for_mfa_totp_strategy
- Unit tests for the app_for_mfa_sms_strategy
- Unit tests for the app_for_forgotten_password_strategy
- Unit tests for the app_for_sessions_strategy
- Updated dependencies
- Updated to the latest version of Typescript
- Some pending unit tests and some updates to the README
- added size-limit, husky, and update-changelog script
- Added biome and publint for linting/formatting, and applied linting
