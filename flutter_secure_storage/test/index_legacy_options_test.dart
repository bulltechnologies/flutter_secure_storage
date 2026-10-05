import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test(
    'legacy identity and backend survive a copy with new biometric options',
    () {
      const legacy = AndroidOptions(
        encryptedSharedPreferences: true,
        sharedPreferencesName: 'legacy-data',
        resetOnError: false,
        keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
        storageCipherAlgorithm: StorageCipherAlgorithm.AES_CBC_PKCS7Padding,
      );
      final copied = legacy.copyWith(
        requireBiometricsPerOperation: true,
        requireBiometricConfirmation: false,
      );
      expect(copied.sharedPreferencesName, 'legacy-data');
      expect(
        copied.toMap(),
        containsPair('encryptedSharedPreferences', 'true'),
      );
      expect(copied.toMap(), containsPair('resetOnError', 'false'));
      expect(
        copied.toMap(),
        containsPair('keyCipherAlgorithm', 'RSA_ECB_PKCS1Padding'),
      );
      expect(
        copied.toMap(),
        containsPair('storageCipherAlgorithm', 'AES_CBC_PKCS7Padding'),
      );
      expect(
        copied.toMap(),
        containsPair('requireBiometricsPerOperation', 'true'),
      );
      expect(
        copied.toMap(),
        containsPair('requireBiometricConfirmation', 'false'),
      );
    },
  );

  test('modern defaults do not opt into a legacy backend or identity', () {
    expect(
      AndroidOptions.defaultOptions.toMap(),
      isNot(contains('encryptedSharedPreferences')),
    );
    expect(
      AndroidOptions.defaultOptions.toMap(),
      isNot(contains('sharedPreferencesName')),
    );
  });
}
