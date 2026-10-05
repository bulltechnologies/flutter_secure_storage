# Index owned secure storage (Darwin)

Vendored from `flutter_secure_storage_darwin` 0.3.2 as resolved by the app's
lockfile, archive SHA-256
`82329fa5cdf343773b1b6897dea959105a29f092454259edff92f9f6637e8149`.
The upstream license is retained in `LICENSE`; the package identity, public
Dart API, Keychain service/account identities and authentication policies stay
unchanged.

Ordinary Keychain upserts preserve the previous item on presence-query or
update errors. Only a proven absent item permits creation. Accessibility and
authentication-policy changes remain the host's explicit recoverable rewrite.
`tests/keychain_upsert_test.swift` tests the production mutation decision with
synthetic storage; it does not access the real Keychain.

`KeychainUpsert` is the injectable ordinary mutation decision. A successful
update returns success without another mutation. Presence errors and all update
errors except `errSecItemNotFound` return their actual platform status, preserving
the prior item. Proven absence, including an item disappearing between presence
and update, permits `SecItemAdd`; add failure propagates. There is no ordinary
delete-and-add fallback. Existing enclave branches and access-control options
are retained.

Host verification commands, from the app repository:

```sh
swiftc -typecheck -module-cache-path /private/tmp/index_fss_swift_module_cache native/flutter_secure_storage_darwin/darwin/flutter_secure_storage_darwin/Sources/flutter_secure_storage_darwin/FlutterSecureStorage.swift native/flutter_secure_storage_darwin/darwin/flutter_secure_storage_darwin/Sources/flutter_secure_storage_darwin/KeychainUpsert.swift
swiftc -module-cache-path /private/tmp/index_fss_swift_module_cache native/flutter_secure_storage_darwin/darwin/flutter_secure_storage_darwin/Sources/flutter_secure_storage_darwin/KeychainUpsert.swift native/flutter_secure_storage_darwin/tests/keychain_upsert_test.swift -o /private/tmp/index_fss_keychain_upsert_test
/private/tmp/index_fss_keychain_upsert_test
```

The full native storage source and helper passed macOS host type checking. The
synthetic test passed authentication/interaction/parameter/unavailable/duplicate
update errors, failed presence checks with zero effects, absent creation,
concurrent missing-item/add failure, and successful update without add. It makes
no Security framework storage calls. Isolated synthetic Keychain integration
tests on iOS/macOS devices, including locked-device error combinations and
process interruption, remain physical-platform qualification; no observed
frequency of the original conditional failure is claimed.
