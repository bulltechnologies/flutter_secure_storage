import Foundation
import Security
import LocalAuthentication

// Link this file with the actual storage engine. Its SecItemUpdate symbol is
// intercepted, so a regression in the write boundary fails without Keychain I/O.
private var capturedQuery: [String: Any]?
private var capturedAttributes: [String: Any]?
private var updateStatus = errSecSuccess
private var addCalls = 0

func SecItemUpdate(_ query: CFDictionary, _ attributes: CFDictionary) -> OSStatus {
    capturedQuery = query as NSDictionary as? [String: Any]
    capturedAttributes = attributes as NSDictionary as? [String: Any]
    return updateStatus
}

func SecItemAdd(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    addCalls += 1
    return errSecSuccess
}

private class ExistingStorage: FlutterSecureStorage {
    override func containsKey(params: KeychainQueryParameters) -> Result<Bool, OSSecError> {
        return .success(true)
    }
}

@main
struct KeychainUpdateQueryTests {
    static func main() {
        let storage = ExistingStorage()
        let context = LAContext()
        var params = KeychainQueryParameters(
            key: "cursor", accessGroup: "test.group", service: "test.service",
            isSynchronizable: false, accessibilityLevel: "unlocked_this_device",
            usesDataProtectionKeychain: true, shouldReturnData: true
        )
        params.authenticationContext = context

        for flag: Bool? in [true, false, nil] {
            params.shouldReturnData = flag
            let response = storage.write(params: params, value: "generation 2")
            precondition(response.status == errSecSuccess)
            let query = capturedQuery!
            for key in [kSecReturnData, kSecReturnAttributes, kSecReturnRef,
                        kSecReturnPersistentRef, kSecMatchLimit] {
                precondition(query[key as String] == nil, "Update contains a result request")
            }
            precondition(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
            precondition(query[kSecAttrAccount as String] as? String == "cursor")
            precondition(query[kSecAttrService as String] as? String == "test.service")
            precondition(query[kSecAttrSynchronizable as String] as? Bool == false)
            precondition(query[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
            precondition(query[kSecUseAuthenticationContext as String] as? LAContext === context)
            precondition(capturedAttributes?[kSecValueData as String] as? Data == Data("generation 2".utf8))
            precondition(addCalls == 0)
        }

        // Verify all result flags independently of which ones the Dart parser
        // currently sets; matching and authentication attributes must survive.
        let matching = KeychainUpsert.matchingQueryForUpdate([
            kSecReturnData: true, kSecReturnAttributes: true, kSecReturnRef: true,
            kSecReturnPersistentRef: true, kSecMatchLimit: kSecMatchLimitOne,
            kSecAttrService: "service", kSecAttrAccessGroup: "group",
            kSecAttrSynchronizable: false, kSecUseAuthenticationContext: context
        ])
        precondition(matching.count == 4)
        precondition(matching[kSecAttrAccessGroup] as? String == "group")

        for failure in [errSecParam, errSecInteractionNotAllowed, errSecAuthFailed] {
            updateStatus = failure
            precondition(storage.write(params: params, value: "new").status == failure)
            precondition(addCalls == 0, "An update error must preserve the existing item")
        }
        print("Passed: production writes omit result flags, retain identity/protection, and preserve items on errors")
    }
}
