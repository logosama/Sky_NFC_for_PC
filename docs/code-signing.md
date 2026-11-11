# Windows code signing: options and how to obtain a certificate

The Windows binaries are unsigned. PyInstaller onefile builds and the DLL
injector can trigger Defender/SmartScreen false positives; the hook DLL and
`OpenProcess`/`WriteProcessMemory`/`CreateRemoteThread` calls make heuristic
detection more likely. A real Authenticode certificate reduces warnings and
lets users verify the publisher, but it does **not** guarantee that antivirus
will never flag DLL injection.

No signing keys or certificates are stored in this repository. The Android
release key lives only in GitHub Actions Secrets. Do not add a private key or
PFX to the repo.

## Options

| Option | Cost | Eligibility | Notes |
|---|---|---|---|
| SignPath Foundation | Free for qualifying OSS | OSI-approved license, actively maintained, no malware/PUA or security-circumvention tooling, public signing policy | Certificates are issued to SignPath Foundation; per-release manual approval; apply and wait for review |
| Microsoft Azure Artifact Signing (ex Trusted Signing) | Basic $9.99/month (5,000 signatures), Premium $99.99/month | Individuals: US/Canada only. Organizations: US/Canada/EU/UK, with verifiable tax history | Short-lived certificates, no hardware token, GitHub Action available; standard certificate, SmartScreen reputation still builds |
| Commercial OV/EV certificate | Roughly $300-500/year | Subject to CA identity/business validation | Private key on a hardware token or cloud HSM; sign with `signtool`; OV builds SmartScreen reputation, EV does not automatically bypass every warning |
| No certificate | Free | — | Use the onedir package, publish SHA256SUMS, add a narrow Defender exclusion only for a trusted extracted folder, and submit false positives to Microsoft |

Self-signed certificates do not help with SmartScreen or Defender and are not a
substitute for a publicly trusted certificate.

## SignPath Foundation

SignPath Foundation offers free Authenticode signing for open-source Windows
projects: <https://signpath.org/>.

Requirements that matter for this repository:

- An OSI-approved license for the project. **This repository currently has no
  LICENSE file.** Adding one (for example MIT) is required before applying.
- The project must be actively maintained and already released.
- The project must not be malware, PUA, or a security-circumvention/hacking
  tool. This project injects a DLL into a game process; that policy is a real
  rejection risk. Describe the project accurately and do not try to hide what it
  does.
- A public code-signing policy page with defined Author/Reviewer/Approver roles,
  MFA on GitHub and SignPath, and the required attribution line.

If accepted, SignPath issues the certificate to SignPath Foundation and signs
through its GitHub Action with a manual approval step. The publisher shown in
the signature is SignPath Foundation, not this repository's owner.

## Microsoft Azure Artifact Signing

Formerly Azure Trusted Signing: <https://learn.microsoft.com/azure/artifact-signing/>.

- Individuals: United States or Canada only, paid Azure subscription, identity
  validated through Microsoft Entra Verified ID.
- Organizations: US, Canada, EU, or UK, with at least three years of verifiable
  tax history.
- Pricing: Basic $9.99/month (5,000 signatures), Premium $99.99/month
  (100,000 signatures).
- Certificates are short-lived (reissued daily) and kept in Microsoft's service;
  no hardware token is required.
- GitHub Actions integration: `azure/trusted-signing-action` (or `signtool`
  with the service's client tools).
- This is a standard certificate; SmartScreen reputation still has to build.

If you are outside the eligible regions, a commercial OV certificate is the
usual alternative.

## Commercial OV/EV certificate

Typical vendors include DigiCert, Sectigo, SSL.com, and Certum. Expect:

1. Identity or business validation by the CA (domain/phone/legal documents).
2. A private key in a FIPS 140-2/3 hardware token or cloud HSM (most CAs no
   longer issue exportable PFX files).
3. Signing with `signtool sign /fd SHA256 /tr <timestamp-url> /td SHA256 ...`
   for `SkyBadgeInject.exe`, `SkyBadgeInjector.exe`, and `sky_hook.dll`.
4. Verification with `signtool verify /pa /v <file>` before publishing.

OV certificates build SmartScreen reputation over time; EV certificates have
historically established reputation faster, but they are not a universal
bypass. Signing also does not prevent behavioral antivirus detection of DLL
injection.

## If you do not sign

This is the current project setup:

- Prefer `SkyBadgeInject-onedir.zip`; it contains the main tool and
  `sky_hook.dll` and injects in-process, so there is no separate injector exe to
  quarantine.
- Verify downloads with `SHA256SUMS`.
- If Defender removes a file, add an exclusion only for the trusted extracted
  folder (not a whole drive or Downloads) and never disable Defender globally.
- Submit false positives to Microsoft:
  <https://www.microsoft.com/en-us/wdsi/filesubmission>.
- Do not attempt to evade antivirus with packing, obfuscation, or renamed
  binaries. The build already uses PyInstaller `--noupx`.

## Integrating a certificate later

Once you have a certificate or signing service:

1. Store the certificate/HSM credentials and passwords in GitHub Actions
   Secrets, never in the repository.
2. Add a signing step to `.github/workflows/windows-release.yml` after the
   Windows build and before the release upload.
3. Sign every PE file that users run: `SkyBadgeInject.exe`,
   `SkyBadgeInjector.exe`, and `sky_hook.dll` (the DLL is loaded by the game, so
   it should be signed too).
4. Run `signtool verify /pa /v` on the staged files; fail the job if any
   signature is invalid.
5. Keep `SHA256SUMS`; signatures and checksums complement each other.
