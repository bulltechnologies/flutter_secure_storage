import Security

/// The ordinary write boundary must never erase a last usable item as error
/// recovery. Keep the platform calls injectable so this rule can be tested
/// without accessing a real Keychain or changing authentication policy.
enum KeychainUpsert {
    static func write<Failure: Error>(
        presence: Result<Bool, Failure>,
        failureStatus: (Failure) -> OSStatus,
        update: () -> OSStatus,
        add: () -> OSStatus
    ) -> OSStatus {
        switch presence {
        case .failure(let error):
            return failureStatus(error)
        case .success(false):
            return add()
        case .success(true):
            let status = update()
            // A concurrent authorized deletion can remove the item between
            // presence and update. That specific result establishes absence.
            return status == errSecItemNotFound ? add() : status
        }
    }
}
