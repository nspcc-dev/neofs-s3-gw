// Package eacloverlay implements conversion between
// NeoFS eACL and S3 access policies.
// Current limitations:
// 1. Canonical user identifiers are expected to contain public key in hex.
// 2. Resource identifiers are expected to contain object id in base 58.
// 3. No wildcards are supported.
//
// All of these limitations can be lifted with some kind of ID-provider which
// is outside of scope of this package.
package eacloverlay

/*
Testcases:
1. Private container, share object with all.
2. Private container, allow list all objects to all.
*/
