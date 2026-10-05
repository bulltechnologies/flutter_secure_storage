# Index storage foundation

This fork retains upstream history and package names. It merges the upstream
`flutter_secure_storage-v11.2.0` release into the existing Index storage patches,
then fixes ordinary iOS Keychain updates without introducing an error-triggered
delete-and-add fallback. It is distributed as a Git dependency, not a new pub.dev
package. Original license and attribution notices are retained.

| Component | Upstream baseline | Fork version |
| --- | --- | --- |
| Flutter entry point and Android plugin | 11.2.0 | 11.2.0+index.1 |
| Shared iOS/macOS implementation | 0.4.3 | 0.4.3+index.1 |
| Platform interface | 2.1.1 | Unmodified upstream interface |

The initial owned-patch commit is based on upstream `v10.3.4`, matching the
previous vendored implementation. Keeping that commit separate makes the
existing recovery protocol distinguishable from the upgrade and the new fix.

## iOS update fix

The native method-channel parser supplies `shouldReturnData: true` for ordinary
writes. The previous native engine reused that lookup query for `SecItemUpdate`.
An existing item could therefore return `errSecParam` (-50). The upstream engine
then deleted and re-added the item after an unsuccessful update; the Index
preservation patch correctly propagated the error, exposing the invalid query.

The fork removes return-data, return-attributes, return-reference,
return-persistent-reference and match-limit fields at the update boundary.
Account, service, access group, synchronizability, accessibility and
authentication attributes remain in the matching query. Reads retain their
result requests. Existing values are updated in place; only proven absence
permits insertion. Other lookup/update errors propagate with no deletion.

Darwin 0.4.3's legacy access-control lookup, macOS data-protection handling and
cross-accessibility lookup changes are included. Finding an older item does not
authorize changing its authentication/accessibility policy. A write with an
incompatible protection query can still fail safely; a policy migration remains
an explicit recoverable operation owned by the host application.

## Android compatibility and guarantees

This is a compatibility-preserving fork of 11.2.0, with intentional differences
from the stock major upgrade:

- Legacy RSA PKCS1/CBC readers, the existing `sharedPreferencesName` option and
  the ESP compatibility backend are retained. Existing storage identities must
  not silently map to a different algorithm or become unreadable because their
  reader was removed. New stores continue to default to RSA OAEP/AES GCM.
- The owned ordinary migration coordinator retains a complete authenticated
  source inventory, isolated target generations, checked persistence boundaries,
  deletion intents, recovery after repeated interruptions, and read-only root
  loading. Ambiguous or opaque legacy recovery state is preserved and refused.
- Explicit namespaced family retirement continues to erase the family's data,
  roots and owned recovery artifacts, and invalidate cached instances. This
  replaces upstream's prefix-only `deleteAll` behavior. Use separate
  `storageNamespace` values for independently owned stores, rather than treating
  multiple prefixes in one family as independent retirement boundaries.
- The 11.x asynchronous read/write interface, fresh authentication option,
  confirmation option, prompt dismissal fix, post-authentication recovery,
  prefix-aware instance caching and OEM non-VM error handling are included.
  Asynchronous continuations retain the owned family lock and retirement epoch
  checks; standard stores complete without an authentication prompt.
- `checkUpgradeStatus` uses read-only root loading and understands active owned
  generations. Pending migration, legacy compatibility data and absent markers
  report `unknown` without initiating migration or promising data loss.
  It is a preflight diagnostic, not proof that every stored value is valid.

The entry point accepts Windows backend versions from 4.1.0 through 4.x. The
11.2.0 Dart storage interface remains compatible with 4.1.0; its Windows options
did not change behavior. This lets an existing mobile host retain a Win32 v5
dependency graph while other consumers can select the newer Win32 v6 backend.
Windows 4.2.2 is retained in the fork workspace. A consumer resolving 4.1.0 does
not receive 4.2.2's backend changes until its other Win32 dependencies are upgraded.

The host must continue using its selected recovery options, including
`resetOnError: false` and `migrateWithBackup: true` for Index ordinary stores.
The post-operation Android persistence barrier implemented by the host remains
required; this fork does not replace that host channel.

See the detailed ownership contracts in
[Android OWNED_PATCHES.md](flutter_secure_storage/OWNED_PATCHES.md) and
[Darwin OWNED_PATCHES.md](flutter_secure_storage_darwin/OWNED_PATCHES.md).

## Consume an immutable revision

Pin both packages to the same full commit SHA. Pinning only the Flutter entry
point would allow its Darwin dependency to resolve to the stock pub.dev package.
Root overrides also make transitive callers use the same native implementation.

```yaml
dependencies:
  flutter_secure_storage:
    git:
      url: https://github.com/bulltechnologies/flutter_secure_storage.git
      ref: <fullCommitSha>
      path: flutter_secure_storage

dependency_overrides:
  flutter_secure_storage:
    git:
      url: https://github.com/bulltechnologies/flutter_secure_storage.git
      ref: <sameFullCommitSha>
      path: flutter_secure_storage
  flutter_secure_storage_darwin:
    git:
      url: https://github.com/bulltechnologies/flutter_secure_storage.git
      ref: <sameFullCommitSha>
      path: flutter_secure_storage_darwin
```

Commit the consumer's lockfile and verify that each resolved Git revision matches
the intended SHA. Release tags are readable labels; the application's full SHA
is the reproducibility boundary.

## Verification

The `Index Storage` workflow runs Dart analysis/API tests, the compiled Android
native suite, the persistence fault-injection suites, the Swift preservation
decision tests, the actual engine's update-query regression test and iOS native
type checking. It does not require upstream publishing or Codecov credentials.
Upstream publishing, deployment and maintenance workflows remain scoped to the
upstream repository.

Local commands, from the fork root:

```sh
flutter pub get
flutter test --no-pub flutter_secure_storage/test
flutter test --no-pub flutter_secure_storage_platform_interface/test

# Java 21 and Gradle 9.3.1; Android SDK installed, Flutter Android artifacts cached.
# FLUTTER_ROOT and ANDROID_HOME identify your installed SDKs.
gradle -p flutter_secure_storage/tests/android :flutter_secure_storage:testDebugUnitTest
sh flutter_secure_storage/tests/host/run.sh /path/to/json-20240303.jar /tmp/fss-host

swiftc flutter_secure_storage_darwin/darwin/flutter_secure_storage_darwin/Sources/flutter_secure_storage_darwin/KeychainUpsert.swift flutter_secure_storage_darwin/tests/keychain_upsert_test.swift -o /tmp/fss-upsert
/tmp/fss-upsert
swiftc flutter_secure_storage_darwin/darwin/flutter_secure_storage_darwin/Sources/flutter_secure_storage_darwin/FlutterSecureStorage.swift flutter_secure_storage_darwin/darwin/flutter_secure_storage_darwin/Sources/flutter_secure_storage_darwin/KeychainUpsert.swift flutter_secure_storage_darwin/tests/keychain_update_query_test.swift -o /tmp/fss-query
/tmp/fss-query
```

Foundation verification passed 94 main-package Dart tests, 21 interface tests,
201 Android native tests and 390 host persistence/interruption cuts plus the
production cipher-root checks. The Swift query test passes with the fixed engine
and fails against the previous engine because its update query requests data.

An isolated physical iOS probe compiled the actual fork engine and called Apple's
Security framework. Existing-item writes with return-data true/false/omitted and
a new item's second write succeeded, retained their persistent references, and
made no deletion call. Direct use of the original return-data query reproduced
-50. Synthetic probe items and the test application were removed afterwards.
No production wallet data or Keychain access group was accessed.

These results do not qualify full wallet startup, locked-device/biometric
combinations, Android hardware KeyStore behavior, or physical process/power
interruption durability. Those remain platform release qualification.

## Maintenance

Keep owned fixes in focused commits with regression tests. Merge reviewed
upstream releases onto the maintained branch; do not replace the tree with a
downloaded archive and overwrite recovery code. Review algorithm, namespace,
deletion, authentication and persistence changes explicitly. Retest recovery
before updating consumer pins, then tag the reviewed foundation revision.

Remove a compatibility path only after the host has a qualified migration and
retirement plan for existing installations. A stock major-version deletion of
legacy readers is not sufficient evidence that stored data is safe to abandon.
