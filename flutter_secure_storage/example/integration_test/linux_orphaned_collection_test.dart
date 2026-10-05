import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Linux integration tests for a missing default alias when matching secure
/// storage data still exists in another collection.
///
/// Reads and mutations must fail closed instead of treating this as a fresh
/// profile or creating a second default collection.
///
/// This suite deletes the current default collection. It is disabled unless
/// explicitly enabled and must only run against an isolated test keyring.

const _storage = FlutterSecureStorage();
const _sentinelKey = 'orphaned_collection_sentinel';
const _sentinelValue = 'preserve-me';
const _sessionCollectionPath = '/org/freedesktop/secrets/collection/session';
const _destructiveTestsEnabled = bool.fromEnvironment(
  'FSS_DESTRUCTIVE_KEYRING_TESTS',
);

Future<ProcessResult> _callDbus(
  String objectPath,
  String method, [
  List<String> arguments = const [],
]) {
  return Process.run('gdbus', [
    'call',
    '--session',
    '--dest',
    'org.freedesktop.secrets',
    '--object-path',
    objectPath,
    '--method',
    method,
    ...arguments,
  ]);
}

Future<String> _readDefaultAlias() async {
  final result = await _callDbus(
    '/org/freedesktop/secrets',
    'org.freedesktop.Secret.Service.ReadAlias',
    ['default'],
  );
  expect(result.exitCode, 0, reason: result.stderr as String);

  final match = RegExp(
    "objectpath '([^']+)'",
  ).firstMatch(result.stdout as String);
  expect(match, isNotNull, reason: result.stdout as String);
  return match!.group(1)!;
}

Future<void> _setDefaultAlias(String collectionPath) async {
  final result = await _callDbus(
    '/org/freedesktop/secrets',
    'org.freedesktop.Secret.Service.SetAlias',
    ['default', collectionPath],
  );
  expect(result.exitCode, 0, reason: result.stderr as String);
}

Future<void> _deleteCollection(String collectionPath) async {
  final result = await _callDbus(
    collectionPath,
    'org.freedesktop.Secret.Collection.Delete',
  );
  expect(result.exitCode, 0, reason: result.stderr as String);
}

Future<void> _ensureDefaultAliasMissing() async {
  final currentAlias = await _readDefaultAlias();
  if (currentAlias != '/') {
    await _deleteCollection(currentAlias);
  }
  expect(await _readDefaultAlias(), '/');
}

Future<void> _expectKeyringUnavailable(
  Future<void> Function() operation,
) async {
  Object? caught;
  try {
    await operation();
  } on Object catch (error) {
    caught = error;
  }

  expect(caught, isNotNull, reason: 'Expected an exception');
  expect(caught, isNot(isA<FormatException>()));
  expect(caught, isA<PlatformException>());

  final error = caught! as PlatformException;
  expect(error.code, 'KeyringLocked');
  expect(error.message, 'KeyringLocked');
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group(
    'Missing default alias with existing data',
    () {
      String? collectionPath;

      setUpAll(() async {
        collectionPath = await _readDefaultAlias();
        expect(collectionPath, isNot('/'));

        await _setDefaultAlias(_sessionCollectionPath);
        await _storage.write(key: _sentinelKey, value: _sentinelValue);

        await _setDefaultAlias(collectionPath!);
        await _deleteCollection(collectionPath!);
        expect(await _readDefaultAlias(), '/');
      });

      setUp(() async {
        await _ensureDefaultAliasMissing();
      });

      tearDown(() async {
        expect(await _readDefaultAlias(), '/');
      });

      tearDownAll(() async {
        await _setDefaultAlias(_sessionCollectionPath);
        expect(await _storage.read(key: _sentinelKey), _sentinelValue);
        await _storage.deleteAll();
      });

      testWidgets('read fails closed', (_) async {
        await _expectKeyringUnavailable(
          () async {
            await _storage.read(key: _sentinelKey);
          },
        );
      });

      testWidgets('write fails closed', (_) async {
        await _expectKeyringUnavailable(
          () => _storage.write(key: 'new-key', value: 'new-value'),
        );
      });

      testWidgets('readAll fails closed', (_) async {
        await _expectKeyringUnavailable(_storage.readAll);
      });

      testWidgets('containsKey fails closed', (_) async {
        await _expectKeyringUnavailable(
          () async {
            await _storage.containsKey(key: _sentinelKey);
          },
        );
      });

      testWidgets('delete fails closed', (_) async {
        await _expectKeyringUnavailable(
          () => _storage.delete(key: _sentinelKey),
        );
      });

      testWidgets('deleteAll fails closed', (_) async {
        await _expectKeyringUnavailable(_storage.deleteAll);
      });
    },
    skip: kIsWeb || !Platform.isLinux || !_destructiveTestsEnabled
        ? 'Linux only; set FSS_DESTRUCTIVE_KEYRING_TESTS=true to run'
        : null,
  );
}
