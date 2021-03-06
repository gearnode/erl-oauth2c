# Introduction
All notable changes to this project will be documented in this file.

The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2021-06-24
### Added
- Add function to parse OAuth2 error contains in URI query parameters.

### Changed
- Update dependencies.
- The function `authorize_url/3` now returns a map instead of `{ok,
  Value}`.

### Fixed
- Client options do not supports `uri:uri()` type as value.

## [0.2.0] - 2021-06-22
### Changed
- Clean request parameters serialization.
- Return authorization and discovery URIs as URI maps instead of URI
  strings.
### Fixed
- Typo in the client object (disovery instead of discovery).

## [0.1.0] - 2020-03-16
### Added
- Support of the [RFC 6749](https://tools.ietf.org/html/rfc6749).
- Support of the [RFC 7009](https://tools.ietf.org/html/rfc7009).
- Support of the [RFC 7662](https://tools.ietf.org/html/rfc7662).
- Support of the [RFC 8414](https://tools.ietf.org/html/rfc8414).
- Support of the [RFC 8628](https://tools.ietf.org/html/rfc8628).
