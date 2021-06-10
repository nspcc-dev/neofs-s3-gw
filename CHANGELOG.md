# Changelog

This document outlines major changes between releases.

## 0.15.0 (10 Jun 2021)

This release brings S3 gateway to the current state of NeoFS and fixes some
bugs, no new significant features introduced (other than moving here already
existing authmate component).

New features:
 * authmate was moved into this repository and is now built along with the
   gateway itself (#46)

Behavior changes:
 * neofs-s3-gate was renamed to neofs-s3-gw (#50)

Improvements:
 * better Makefile (#43, #45, #55)
 * stricter linters (#45)
 * removed non-standard errors package from dependencies (#54)
 * refactoring, reusing new sdk-go component (#60, #62, #63)
 * updated neofs-api-go for compatibility with current NeoFS node 0.21.0 (#60,
   #68)
 * extended README (#67, #76)

Bugs fixed:
 * wrong (as per AWS specification) access key ID generated (#64)

## Older versions

Please refer to [Github
releases](https://github.com/nspcc-dev/neofs-s3-gw/releases/) for older
releases.
