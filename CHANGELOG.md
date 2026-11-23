# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.2] - 2026-11-23

### Added
- README: added best practice synchronization frequency warning. Run once; if scheduled, maximum once per month.

## [1.2.1] - 2025-10-21

### Fixed
- Typo in the correlation property comments.
- Verbose logging: messages that were always written are now only written when verbose logging is enabled.

## [1.2.0] - 2023-12-22

### Changed
- Use the new HelloID products API.
- Default product SKU prefix changed from `ADGRP` to `APPGRP`.
- Restructured the configuration section and logging.

## [1.1.0] - 2023-09-13

### Added
- Comment `Synchronized assignment from AD Groupmembership` on the product assignments.

### Changed
- Default correlation changed from `SID` / `immutableId` to `UserPrincipalName` / `username`.
- Group members are retrieved with an LDAP `memberOf` filter instead of `Get-ADGroupMember`.

### Fixed
- Groups in the configured OU are queried with search scope `OneLevel`.

## [1.0.0] - 2023-06-26

Initial release with base functionality: synchronizes Active Directory group memberships to HelloID Self service product assignments.
