# Windows build entry points

Compile unsigned user-mode components from 64-bit PowerShell:

```powershell
.\Windows\compile.ps1 -NoSign -UserModeOnly -OutputDirectory C:\build\ProxyBridge-new
```

Requires MSVC, MSBuild and Windows SDK. Defaults for CI are v143 and
10.0.26100.0; an existing VS2026 lab can explicitly pass `-PlatformToolset v145
-WindowsSdkVersion 10.0.28000.0`. Omit `-UserModeOnly` only with the matching
WDK installed to also compile the unsigned driver. No tool is installed.

The destination must be new. Compilation uses a source snapshot under its
`intermediate` directory, preserves old artifacts and running applications,
and writes build-result.json only after all requested components succeed.
This is not an installable driver package; intermediate files are not shipped.
The five application outputs are Core, GUI, CLI, driver helper and launcher.

Signed packaging is a separate entry point:
`Windows/installer/build-signed-package.ps1`. Supply its explicit manifest,
launcher and publisher hashes, versions, verified signed payload, SignTool,
MakeNSIS, timestamp service and a new destination. Existing verification must
succeed; compile.ps1 never signs or creates certificates. Production release automation remains gated pending signing integration.

The normal Windows CI job builds user mode only, including PRs to Driver.
GitHub-hosted execution is not yet verified by the local build.
Runner inventory: https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md
Release workflow intentionally stops before compilation/upload until a production
release invocation is configured. It cannot publish the unsigned CI outputs.

## Reuse a separately signed driver in one installer

First sign the five application outputs with the intended publisher certificate.
Keep a complete Microsoft-returned driver directory (INF, CAT, SYS), and record
its approved catalog and SYS SHA256 values. Do not rebuild or edit its contents.
Application-only releases can reuse that driver when the protocol and version
contract remains compatible.

```powershell
$inputArgs = @{
    ApplicationDirectory = 'C:\release\signed-app'
    DriverDirectory = 'C:\release\microsoft-driver'
    ExpectedDriverCatalogHash = $approvedCatalogSha256
    ExpectedDriverBinaryHash = $approvedSysSha256
    Protocol = 4
    DriverVersion = 65537
    AppVersion = $appVersion
    Destination = 'C:\release\new-prepared'
}
$prepared = & .\Windows\installer\prepare-package-inputs.ps1 @inputArgs
```

Preparation preserves all original inputs, checks the declared contract against
this checkout's header, pins driver hashes before and after copying, and creates
a manifest. It does not certify signatures or independently infer binary ABI;
use application binaries built from the matching checkout.

Pass `$prepared.ManifestHash`, `$prepared.LauncherHash`, the new payload folder
and launcher to `installer/build-signed-package.ps1`, together with its required
publisher certificate/tool/version/timestamp arguments. Keep its default
`DriverSignaturePolicy=KernelPolicy` for the production driver route. That step
verifies publisher signatures, kernel catalog policy, INF/SYS membership and all
manifest bytes before NSIS. It signs generated uninstaller and final setup.

The result is one ProxyBridge-Setup.exe containing app and driver. The current
NSIS gate still marks it as a rehearsal; do not publish as a production release
until production signing and release integration are completed. There is no automatic Microsoft
submission/download step and no dependency on signing private keys in ordinary CI.
## Installed layout and lifecycle

Setup installs one application in `%ProgramFiles%\InterceptSuite\ProxyBridge`.
The GUI, CLI, core, launcher, helper, uninstaller and driver package inputs live
there. Updates overwrite that directory; no previous application versions or
rollback copies are retained. Windows manages the installed driver separately
in its Driver Store. User profiles remain user data.

Start menu/Desktop shortcuts and the startup task use the fixed installation
folder. Registration and cleanup verify ownership before changing existing
files or links. Migration removes recognized legacy `versions` and ProgramData
bootstrap files; unknown files and foreign shortcuts are preserved.

Interrupted installation remains launch-blocked until Setup is run again with
a complete signed payload. The journal, signature validation and recovery code
are required runtime components, not development tests.

Uninstall removes application files, registration and owned shortcuts even when
Windows retains the removed driver's service until restart. In that case the
wizard's final page requests a reboot; reboot before reinstalling. Do not
manually delete Driver Store files or unrelated service entries.

## Validation

CI compiles unsigned user-mode components. Before distributing a build, verify
the signed package and exercise install, update, uninstall/reboot/reinstall and
TCP/UDP traffic on a dedicated Windows test machine. Driver changes also require
the applicable HLK checks and DVL evidence; preserve `driver/create-dvl.ps1` for
that workflow. Passing local compilation is not proof of runtime or HLK success.

Developer test/benchmark harnesses and historical installer reports are retained
in Git history (`codex/windows-full-20260927`), not in the distributable branch.
