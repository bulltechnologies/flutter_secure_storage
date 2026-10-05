# Index owned secure storage (Android and Dart entry point)

Vendored from `flutter_secure_storage` 10.3.4 as resolved by the app's lockfile,
archive SHA-256
`fe638107c5f69119156ada2db5a57734385fac3f64430bd7252a00d3ead2ca4b`.
Upstream licenses, package identity and public Dart API are retained. Apple
native corrections live in the separately owned `flutter_secure_storage_darwin`
package. Select both packages in the host's dependency graph.

The owned native persistence changes keep logical keys, configured namespaces,
encryption profiles and authentication policies. Ordinary migration preserves
an authenticated complete source inventory and uses isolated target generations.
`MigrationArtifacts` defines the internal artifact grammar and family lock shared
with host exact/family deletion. Unknown recovery state is preserved and denied.

## Ordinary Android persistence

The app and WalletCore keep their existing RSA OAEP/AES GCM options,
`resetOnError:false`, `migrateWithBackup:true`, preference identities, and App
Lock behavior. `OrdinaryMigration` also converts a complete readable ordinary
CBC/PKCS1 source described by the upstream supported algorithm markers. The
storage-cipher-only conversion now inventories the source in the same way as a
key-cipher conversion.

The coordinator records an immutable, sorted inventory of all canonical source
records, including ciphertext hashes and keyed plaintext verifiers. Plaintext
verifiers use a separate HMAC domain bound to source root, exact family,
generation, logical key, and plaintext, preventing a public plaintext dictionary
oracle. Both generation proofs use
a domain-separated HMAC derived from the actual source/target application root
and bind the exact effective data preference family, algorithms, generations,
and complete inventory. Source root loading is read-only: missing, unreadable,
or differently typed source keys are preserved and refused.

`prepared` authority is checked on disk before complete source snapshots are
created. Target wrapping aliases and root slots use an isolated random generation.
Target roots and a `ready` journal persist before any canonical ciphertext is
replaced. Replacement is committed as one complete batch and every retained
record is verified under the target. `published` authority, active generation,
and algorithm markers commit together before any source cleanup. Published
recovery verifies current target records and retries only cleanup, preserving
subsequent legitimate writes. A cleanup failure retains the published journal.

An already-durable exact deletion intent is completed before publication or
cleanup even if its original canonical erase failed. Before publication this
applies only to inventoried source records. After publication it also covers
later exact logical records within the configured prefix and current generation,
because normal target writes may continue while cleanup is pending. Completion
uses a checked data barrier before retiring the finite intent. Other prefixes,
generations, and untombstoned siblings retain their records/markers.

A cached writer cannot recreate an exact key while that generation's deletion
intent can erase it on reopen. `OrdinaryMigration.beforeWrite` completes published
recovery and cleanup first, refusing without acknowledgment while intent remains
or the source is unpublished. Only durably retired intent permits recreation.
The plugin also certifies configuration before writes, covering a failed cleanup
that made journal/intent absent in RAM only. This prevents a successful write from
being erased on the next restart without discarding deletion authority.

`CheckedPreferences` checks every commit and forces a changed preference
generation, so a retry cannot mistake a RAM-only prior write for disk publication.
Existing journals are re-certified before their dependent effects, including
same-process retries after failed commits. Ordinary record writes and root
creation also use checked persistence. A generated root loaded from RAM on a
fresh-store retry is certified before dependent ciphertext can be acknowledged.

## Host integration contract

`com.it_nomads.fluttersecurestorage.MigrationArtifacts` owns the grammar. The
host should import these helpers rather than duplicate a permissive parser.

- `familyLock(String effectiveDataPrefsName)` returns one stable in-process lock
  for the exact physical data family. Native migration, plugin dispatch, and
  host erasure share it.
- `invalidateFamily(String): long` increments that family's cache epoch;
  `familyEpoch(String): long` reads it. Call invalidation under the family lock
  before a full family erase. The plugin then discards cached preferences/ciphers
  at initialization and rejects stale dispatch/authentication continuations.
  This is an in-process cache guard; durable deletion intent belongs to the host.
- `MANIFEST = __fss_migration_v1`,
  `ACTIVE_GENERATION = __fss_active_generation_v1`, and
  `DELETED_PREFIX = __fss_deleted_v1__` are scoped configuration entries.
- `sourceCopyKey(generation, canonicalKey)` creates
  `__fss_source_v1__<32 lowercase hex generation>__<exact canonical key>`.
  `canonicalKeyFromSourceCopy(String)` returns the exact canonical suffix only
  after generation grammar validation, otherwise null.
  `isSourceCopyKeyFor(physical, canonical)` matches exact logical ownership.
- `GENERATION_SUFFIX = __FSSGEN__` is appended to ordinary wrapping aliases and
  wrapped-root slots. `isGenerationAliasFor(alias, packageName, namespace)`
  recognizes only the exact RSA18/OAEP base plus one valid generation.
- `recordKeyDeletion(SharedPreferences scopedConfig, String canonicalKey)` must
  run under the family lock before removing canonical/source-copy bytes. It
  durably suppresses that logical record only for the pending migration
  generation. Cleanup retires the suppression with that generation, permitting
  later explicit recreation.

Plugin `delete(key)` applies finite suppression and removes matching source
copies; documented legacy `_BACKUP`/`_MIGRATED` siblings are erased only when
existing migration metadata grants that ownership. `readAll` exposes canonical
logical entries. A full isolated-family clear removes its configuration,
wrapped roots, and exact namespaced generation aliases. Default unnamespaced
clears preserve common wrapping roots/aliases that can protect other data
families. The application's dedicated native erasure paths complete the wider
custody and product lifecycle integration.

## Regression verification

Run the synthetic host suite with an already installed `org.json` jar:

```sh
sh native/flutter_secure_storage/tests/host/run.sh /absolute/path/to/org.json.jar /private/tmp/index_owned_fss_host_tests
```

It compiles the production coordinator, checked preference helper, artifact
grammar, configuration, ordinary CBC/GCM root loaders, and keyed proof helper.
Fixtures maintain separate RAM and disk state. The suite passed 198 failed-commit,
process-stop, repeated-recovery, same-process-retry, and retry-then-stop cases
across 33 persistence boundaries, plus 108 ready/published exact deletion recovery
cuts. It also covers complete inventory refusal,
missing/corrupt source preservation, manifest tampering, copied-family replay,
orphan/unknown artifacts, exact deletion/recreation, cleanup after later target
writes, failed erasure after durable intent, erasure of later target revisions,
unrelated deletion-marker preservation, keyed plaintext-verifier privacy, cache
epoch stability, isolated root slots, read-only legacy root loading, and failed
target-root commits. Upstream STARTED-discard and ESP-skip tests now assert
preservation/refusal rather than the former unsafe successful cleanup.
Another 84 recreation preflight cuts cover failed commits, process stops and
same-process retry before an acknowledged recreated value is cold-reopened.
`CachedRecreationTest` exercises actual plugin cached initialization, exact delete,
refused recreation during cleanup failure and successful later recreation with
synthetic roots through Robolectric; the central plugin unit task runs it.

The synthetic wrapping provider uses test-only keys, and the CBC fixture maps
Android's PKCS7 transformation name to the equivalent host PKCS5 provider name.
The suite never accesses Android KeyStore, real preferences, or user secrets.
Physical Android fault injection, hardware-backed key lifecycle, application
plugin-cache integration, and device restart qualification remain separate
integration checks. The host's central build owns Gradle/Flutter qualification.

Historical biometric/ESP conversion and the non-backup conversion path are not
newly supported by this change. Current app admission preserves and refuses
ambiguous legacy flags, orphan copies, and opaque ESP records; no automatic
legacy importer, authentication prompt, or destructive fallback was introduced.
