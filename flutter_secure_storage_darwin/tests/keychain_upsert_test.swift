import Security

private struct StatusError: Error { let status: OSStatus }

@main
struct KeychainUpsertTests {
    static func main() {
        for error in [errSecAuthFailed, errSecInteractionNotAllowed, errSecParam,
                      errSecNotAvailable, errSecDuplicateItem] {
            var record: String? = "previous usable root"
            var adds = 0
            let status = KeychainUpsert.write(
                presence: Result<Bool, StatusError>.success(true),
                failureStatus: { $0.status },
                update: { error },
                add: { adds += 1; record = "replacement"; return errSecSuccess }
            )
            precondition(status == error && adds == 0 && record == "previous usable root")
        }
        var effects = 0
        let presenceError = KeychainUpsert.write(
            presence: Result<Bool, StatusError>.failure(StatusError(status: errSecNotAvailable)),
            failureStatus: { $0.status },
            update: { effects += 1; return errSecSuccess },
            add: { effects += 1; return errSecSuccess }
        )
        precondition(presenceError == errSecNotAvailable && effects == 0)
        var adds = 0
        let missing = KeychainUpsert.write(
            presence: Result<Bool, StatusError>.success(false),
            failureStatus: { $0.status },
            update: { preconditionFailure("Absent item must not update") },
            add: { adds += 1; return errSecSuccess }
        )
        precondition(missing == errSecSuccess && adds == 1)
        let concurrentDeletion = KeychainUpsert.write(
            presence: Result<Bool, StatusError>.success(true),
            failureStatus: { $0.status },
            update: { errSecItemNotFound },
            add: { adds += 1; return errSecDuplicateItem }
        )
        precondition(concurrentDeletion == errSecDuplicateItem && adds == 2)
        let successfulUpdate = KeychainUpsert.write(
            presence: Result<Bool, StatusError>.success(true),
            failureStatus: { $0.status },
            update: { errSecSuccess },
            add: { preconditionFailure("Successful update must not add") }
        )
        precondition(successfulUpdate == errSecSuccess)
        print("Passed: update failures preserve previous items; presence failures have zero effects; only proven absence adds")
    }
}
