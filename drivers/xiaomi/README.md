# Xiaomi Cloud Recordings

Storage for recordings already synchronized to Xiaomi Cloud. This driver runs inside OpenList; it does not require XiaomiAlbumSyncer, a companion WebDAV server, Python, OpenSSL, or a separate listener.

## Configuration

- **Username**: Xiaomi phone number, email, or account ID.
- **Password**: required on first login. After initialization it is cleared and a credential-equivalent MD5 hash is retained in the saved addition. Entering a new password explicitly performs password authentication, even if an existing session is valid.
- **Send SMS**: only enable after the storage reports a phone-verification challenge, then save. Sending is user driven; the checkbox resets automatically.
- **SMS code**: enter the received code and save. Verification requests device trust and retains the resulting credentials. The code is cleared after use.
- **Device ID / Device fingerprint**: generated on first use and retained. An existing trusted browser's values may be used for migration. Do not routinely regenerate these values.

`session` and `password_hash` are automatically persisted in OpenList's storage addition and omitted from the configuration form. The existing frontend retains these fields when an existing storage is edited. Changing the account clears its previous authentication state; device identity is retained.

Recordings appear in one root directory. A readable filename is followed by the unique cloud ID to avoid collisions after removing Xiaomi's metadata suffix. Cloud SHA1 is exposed through `HashInfo`. Cloud deletion uses the captured non-permanent deletion endpoint (`permanent=false`). Permanent deletion, uploads, renames, and directory creation are not implemented. Local NAS backups are retained. The effect on phone synchronization and the cloud recovery retention period have not been verified.

## Authentication and download behavior

Authentication uses `sid=i.mi.com`, retaining the signed callback obtained from the cloud login entry. The username is encrypted using the current Xiaomi frontend's AES-CBC/RSA envelope; cryptography uses Go's standard library. Cookies retain domain, path and expiry. `deviceId`, `deviceFingerprint`, `pass_ptd` and updated account/service tokens survive OpenList restarts.

The driver refreshes the service session on demand every ten minutes. An invalid saved login can trigger at most one automatic password attempt per fifteen minutes. It does not automatically send SMS. A cloud authentication error is retried once after refreshing the session.

Listings are fetched in pages of 500, with duplicate detection and an advancing-pagination guard. Downloads resolve recorder storage JSON and its signed JSONP URL, then POST the download metadata. `RangeReader` performs these requests within OpenList. If the cloud ignores Range on POST, it discards the prefix and limits the response rather than returning wrong bytes. Authentication cookies are never attached to the signed download client; unexpected authentication hosts and download redirects are rejected. Errors omit credentials, response bodies and signed URLs.

Mounting is separate from backing up: a local copy task is still needed to retain recordings on a NAS. This driver does not schedule backups or manage a local archive.

## Validation

```sh
go test ./drivers/xiaomi ./internal/op ./internal/driver
go vet ./drivers/xiaomi
```

Unit tests cover pagination, millisecond timestamps, encrypted password login with signed callbacks, credential-host isolation, POST ranges including full-response fallback, filename isolation, explicit SMS/trusted-device flow, account changes and upload restrictions. HTTP 401 and cloud authentication errors exercise one refresh-and-retry, including a persistent failure that must stop after the second API request.

`go test ./...` was also attempted on Windows with Go 1.27.1. It failed in 15 existing packages. The same command against a pristine archive of the identical upstream commit failed in the identical 15 packages, including pre-existing vet format-string errors, unavailable aria2 services, transport assumptions and Windows temporary-file cleanup. The changed driver's targeted tests passed. The full suite is not claimed to pass; upstream CI and these baseline failures must be considered before public submission.

An optional live test reads an **external private file** whose contents match `Addition`. It contains credentials and must not be committed:

```sh
XIAOMI_TEST_ADDITION=/private/path/addition.json go test ./drivers/xiaomi -run TestLiveCloud -v
```

Live validation on one account covered all 3,426 recordings, SHA1/size of a downloaded sample, cloud byte ranges, password authentication with a freshly encrypted account identifier, and persisted credentials. A custom Linux amd64 OpenList build with the official v4.2.6 frontend was tested on fnOS using a separate data directory and port. Storage editing, disable/enable, native proxy downloading, and OpenList process restart were verified.

The user confirmed browser playback and downloading. Two additional live recovery checks expired the saved service credentials, then expired both service credentials and passToken while retaining device trust. The first recovered through the saved account session; the second automatically used password authentication. Both preserved device identity, restored all 3,426 entries and passed full/range download checks. These checks simulate expiry; they do not establish months-long stability.

The driver-owned SMS flow has been validated with protocol fixtures, not against a new live verification challenge. Image CAPTCHA, other verification methods, a second account, a fresh untrusted device, months-long session stability, and a full NAS reboot remain unverified. Failures requesting other authentication methods are reported as user action, without attempting to bypass Xiaomi verification.

Protocol behavior was independently implemented from successful browser captures and live requests. XiaomiAlbumSyncer was consulted for the overall token-refresh approach. This driver does not import or invoke that project. The API is private and can change.

This contribution was developed with Codex assistance and is subject to OpenList's contribution and AI-disclosure policies. Public submission should follow local user testing and meaningful human review. No real HARs, tokens or recording metadata belong in an upstream contribution.

Deletion refreshes authentication before submitting one POST with the current service token. A network error or cloud error does not automatically replay the mutation, since it may already have been applied. Fixture tests cover success, API errors, lost responses, and invalid targets. No real recording was deleted by automated driver tests. Live driver deletion remains unverified until a user chooses a disposable recording.
