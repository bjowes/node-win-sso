# Changelog

## 1.3.3 - released 2025-05-06

* Dependency bump

## 1.3.2 - released 2025-01-27

* Corrected packaging

## 1.3.1 - released 2025-01-27

* Dependency bump

## 1.3.0 - released 2022-09-21

* Make authentication context flags configurable

## 1.2.0 - released 2022-09-19

* Dependency bump
* Improved Kerberos 
  - delegation support
  - set SPN earlier
  - added security flags

## 1.1.8 - released 2022-04-23

* Dependency bump
* Replaced tslint with eslint

## 1.1.7 - released 2022-02-09

* Patch release, add missing dist folder from 1.1.5

## 1.1.6 - released 2022-02-09

* Patch release, add missing prebuilds from 1.1.5

## 1.1.5 - released 2022-02-09 *deprecated*

* Dependency bump

## 1.1.4 - released 2021-08-23

* Migrated prebuild to GitHub Actions
* Dependency bump

## 1.0.1 - released 2019-12-19

* Return empty header if no token was generated

## 1.0.0 - released 2019-12-15

* Refactored with authentication state handling
* Support for Negotiate

## 0.3.1 - released 2019-10-10

* Patched return statement

## 0.3.0 - released 2019-10-09

* Detect if incoming challenge is NTLMv1 and the client is not permitted to use NTLMv1
* Graceful error handling - allows nested errors from the native module

## 0.2.15 - released 2019-10-04

* Repair npm packaging

## 0.2.14 - released 2019-10-04

* Accept undefined targetHost in createAuthResponse and createAuthResponseHeader
  
## 0.2.13 - released 2019-09-29

* Graceful handling of prebuilds on non-Windows OS

## 0.2.12 - released 2019-09-29

* Prebuild functional

## 0.2.8 - 0.2.11 - released 2019-09-29

* Attempts to added prebuild on Win32 through Appveyor
* First unit tests

## 0.2.7 - released 2019-09-28

* Include full source in npm to avoid quirky issues with rebuild of installed modules

## 0.2.6 - released 2019-09-28

* More graceful failure on non-Window OS

## 0.2.5 - released 2019-09-28

* Fixed npm package contents

## 0.2.4 - released 2019-09-28

* Fixed npm package contents

## 0.2.3 - released 2019-09-28

* Fixed npm package contents

## 0.2.2 - released 2019-09-28

* Made all WinSso methods static

## 0.2.1 - released 2019-09-28

* Added graceful failure on non-Windows OS
* Documented API

## 0.2.0 - released 2019-09-27

* First functional release
