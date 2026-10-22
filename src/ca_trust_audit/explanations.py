"""Per-finding explanations served by ``emudhra-trust-audit explain <FINDING_ID>``.

Every finding the tool can emit has an entry here: what it means, how it was
determined, what to do, and what it does not prove. Findings derived from the
textual ruleset fall back to the rule's own description in ``data/``.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional

from .datafiles import DataBundle


@dataclasses.dataclass(frozen=True)
class Explanation:
    meaning: str
    determined_by: str
    what_to_do: str
    does_not_prove: str


def _e(meaning: str, determined_by: str, what_to_do: str, does_not_prove: str) -> Explanation:
    return Explanation(meaning, determined_by, what_to_do, does_not_prove)


CATALOG: Dict[str, Explanation] = {
    "ENDPOINT-COMMANDS-SKIPPED": _e(
        "Executable probes were skipped; this is a coverage gap.",
        "The command runner was disabled, as it is by default.",
        "Review installed tools and explicitly opt in with --commands if appropriate.",
        "File-only scanning cannot determine runtime versions or query protected OS stores.",
    ),
    "ENDPOINT-SPKI-TRUSTED": _e(
        "A public key listed in the indicator data was found in a store a client reads as trusted.",
        "The SHA-256 of each certificate's SubjectPublicKeyInfo in the store was compared with the indicator list.",
        "Update the component that owns the store, restart the processes using it, then re-run.",
        "It does not prove client acceptance or that a forged certificate was ever presented.",
    ),
    "ENDPOINT-SPKI-DISTRUSTED": _e(
        "A compromised key was found in an explicit block list - the desired state.",
        "The key was found in Windows Disallowed or a p11-kit blocklist directory.",
        "Nothing. Keep the block list in place.",
        "It does not prove that every client on this machine consults that block list.",
    ),
    "ENDPOINT-SPKI-IN-SOURCE-POOL": _e(
        "A compromised intermediate sits in an on-disk pool that is trusted only when configuration selects it.",
        "The key was found under a distribution pool directory, not in a generated trust bundle.",
        "Check whether the entry is enabled and update the package that owns the pool.",
        "Presence in a pool is not trust.",
    ),
    "ENDPOINT-SPKI-ABSENT": _e(
        "None of the compromised keys were found in the stores that could be read.",
        "Every readable trust source was parsed and compared with the indicator list.",
        "Nothing on its own; read the version and revocation findings alongside it.",
        "A server can present the compromised intermediate itself, so absence from a local store is not safety.",
    ),
    "ENDPOINT-STORE-UNREADABLE": _e(
        "A trust store exists but could not be read, so its contents are unknown.",
        "A read or an enumeration command failed.",
        "Re-run with sufficient privileges, or inspect the store with the platform's own tool.",
        "It is neither a pass nor a failure.",
    ),
    "ENDPOINT-NO-STORE-FOUND": _e(
        "No known trust store location exists on this machine.",
        "Each documented path for the detected platform was probed.",
        "Pass --bundle with the CA bundle this machine actually uses, or report the platform as unsupported.",
        "Nothing was compared, so nothing was ruled out.",
    ),
    "ENDPOINT-RELATED-ROOT-PRESENT": _e(
        "A root that issued or cross-signed the affected intermediates is installed. This is expected.",
        "Subject common names in the trust sources were compared with the related-root list.",
        "Nothing. Removing such a root by hand breaks unrelated certificates.",
        "Root presence says nothing about whether the compromised keys are blocked.",
    ),
    "ENDPOINT-INDEPENDENT-STORES": _e(
        "Runtimes with their own trust store were found; OS patches do not update them.",
        "Node.js, certifi and Java truststores were located and parsed where possible.",
        "Update each runtime through its own channel.",
        "It is an inventory record, not a verdict.",
    ),
    "ENDPOINT-LINUX-CA-CONF": _e(
        "Related root entries were found in /etc/ca-certificates.conf; a leading '!' excludes them.",
        "The configuration file was read and matched against the related-root names.",
        "Nothing directly; use it to interpret the generated bundle.",
        "The file describes intent, not what a running process loaded.",
    ),
    "ENDPOINT-WINDOWS-CTL-DISABLED": _e(
        "Policy prevents this machine from receiving automatic certificate trust list updates.",
        "The AuthRoot policy key DisableRootAutoUpdate was read.",
        "Have the policy owner re-enable CTL updates or distribute the untrusted list through a managed channel.",
        "It does not show whether the machine is currently trusting the compromised keys.",
    ),
    "ENDPOINT-WINDOWS-CTL-ENABLED": _e(
        "No policy disables automatic certificate trust list updates.",
        "The AuthRoot policy key was read and no disabling value was present.",
        "Keep Windows Update current.",
        "It does not prove the untrusted list has been applied yet.",
    ),
    "ENDPOINT-WINDOWS-CTL-UNKNOWN": _e(
        "The automatic trust list policy could not be read.",
        "The registry query failed or PowerShell was unavailable.",
        "Confirm with the administrator that CTL updates are permitted.",
        "Nothing either way.",
    ),
    "ENDPOINT-CA-PACKAGE-OUTDATED": _e(
        "The installed OS CA bundle package is below the version recorded as fixed.",
        "The package manager was queried read-only and the version compared with data/policies/fixed-versions.json.",
        "Update from the distribution's official channel, restart services, rebuild images.",
        "A version below the fix is evidence of work to do, not proof that a forged chain is accepted.",
    ),
    "ENDPOINT-CA-PACKAGE-CURRENT": _e(
        "The installed CA bundle package is at or above the recorded fixed version.",
        "Package manager query plus version comparison.",
        "Restart long-running processes if you have not since the update.",
        "A running process may still hold the pre-update bundle in memory, and the policy table can lag the distribution.",
    ),
    "ENDPOINT-CA-PACKAGE-UNKNOWN": _e(
        "The installed CA bundle version could not be determined.",
        "The package manager query failed or returned nothing.",
        "Query the package manager by hand and compare with the policy file.",
        "Nothing either way.",
    ),
    "ENDPOINT-CA-PACKAGE-UNCOMPARABLE": _e(
        "The installed version and the policy version are not comparable.",
        "Both strings failed the comparison rules for the declared scheme.",
        "Compare by hand against your distributor's advisory.",
        "Nothing either way.",
    ),
    "ENDPOINT-CA-PACKAGE-NO-POLICY": _e(
        "No fixed-version row exists for this platform.",
        "The detected distribution id and version matched no entry in the policy data.",
        "Check your distributor's advisory; contributing a row is welcome.",
        "Absence of a policy row says nothing about the platform's state.",
    ),
    "ENDPOINT-COMPONENT-OUTDATED": _e(
        "A runtime, CA-bundle library or developer CLI is below its recorded fixed release.",
        "Its own --version output was compared with the policy branch that covers it.",
        "Update it from its official channel and restart anything using it.",
        "Version evidence only.",
    ),
    "ENDPOINT-COMPONENT-CURRENT": _e(
        "A component is at or above its recorded fixed release.",
        "Version query plus policy comparison.",
        "Restart processes started before the update.",
        "It does not prove the process in memory uses the new trust data.",
    ),
    "ENDPOINT-COMPONENT-BRANCH-UNKNOWN": _e(
        "The component runs on a release branch the policy does not cover.",
        "The installed version fell outside every recorded branch.",
        "Check upstream release notes, or move to a supported branch.",
        "A branch with no recorded fix is not a branch with no problem.",
    ),
    "ENDPOINT-COMPONENT-NO-POLICY": _e(
        "The component's version was recorded but no fixed version is known to this data set.",
        "A version query succeeded; the policy has no entry for it.",
        "Check the vendor's advisory.",
        "It is context only.",
    ),
    "ENDPOINT-COMPONENT-UNCOMPARABLE": _e(
        "The component version could not be compared with the policy.",
        "Version parsing failed on one of the two strings.",
        "Compare by hand.",
        "Nothing either way.",
    ),
    "ENDPOINT-CLIENT-VERSION": _e(
        "The version of a TLS-using client was recorded as context.",
        "The client's own version flag was run.",
        "Use it when deciding which clients to re-test after an update.",
        "Which trust store the client reads depends on how it was built, so the version decides nothing.",
    ),
    "ENDPOINT-JAVA-PRESENT": _e(
        "A JDK or JRE was found; Java trusts the CAs in its own cacerts file.",
        "java -XshowSettings:properties was read for java.home.",
        "Update the JDK from its vendor and restart Java services.",
        "It does not say whether that truststore contains a compromised key - see the store findings.",
    ),
    "ENDPOINT-GIT-VERIFY-DISABLED": _e(
        "git is configured to accept any TLS certificate.",
        "git config --get http.sslVerify returned a false value.",
        "Remove the setting; use http.sslCAInfo for a private CA instead.",
        "It is a bigger problem than this incident and is independent of it.",
    ),
    "ENDPOINT-GIT-CUSTOM-CA": _e(
        "git reads trust anchors from a custom bundle instead of the OS store.",
        "git config --get http.sslCAInfo returned a path, which was then scanned.",
        "Rebuild that bundle from an updated source, or unset the option.",
        "A custom bundle is legitimate in proxied environments; it is not itself a compromise.",
    ),
    "ENDPOINT-CA-OVERRIDE-ENV": _e(
        "Environment variables point clients at a CA bundle other than the OS store.",
        "A fixed list of CA-override variable names was read from the environment.",
        "Confirm each bundle is current, or unset the variable.",
        "Only the variable name and path are reported; no other environment value is read.",
    ),
    "ENDPOINT-VERIFICATION-DISABLED-ENV": _e(
        "An environment variable switches off certificate verification entirely.",
        "A fixed list of variable names and their disabling values was checked.",
        "Unset the variable in the profile, script or CI definition that sets it.",
        "This is the first thing to fix; everything else in the report is secondary to it.",
    ),
    "ENDPOINT-VERIFICATION-ENV-CLEAN": _e(
        "No environment variable disables certificate verification.",
        "The same fixed list was checked and nothing matched.",
        "Nothing.",
        "Settings inside configuration files and source code are covered by the project audit, not here.",
    ),
    "ENDPOINT-PROXY-CONFIGURED": _e(
        "An HTTP(S) proxy is configured for this environment.",
        "Proxy variable names were checked for presence; values were deliberately not read.",
        "Interpret online test results with the proxy in mind.",
        "A proxy is not a compromise, but a TLS-inspecting proxy invalidates online conclusions.",
    ),
    "ENDPOINT-CONTAINER-CONTEXT": _e(
        "The audit is running inside a container, so the result describes the image.",
        "Container marker files and /proc/1/cgroup were inspected.",
        "Rebuild the image once its base ships the fix, and audit the host separately.",
        "A patched host says nothing about an unrebuilt image.",
    ),
    "ENDPOINT-WSL-CONTEXT": _e(
        "The audit is running inside WSL, which has its own Linux trust store.",
        "WSL_DISTRO_NAME or /proc/version was inspected.",
        "Audit the Windows host separately from a Windows shell.",
        "Patching Windows does not patch the WSL store.",
    ),
    "ENDPOINT-CREDENTIAL-REVIEW": _e(
        "A possible exposure window needs review; presence alone does not establish interception.",
        "Raised only when another finding showed trusted compromised keys or disabled verification.",
        "Follow the conditional steps in the finding, which follow public incident-response guidance.",
        "The tool cannot determine whether any credential was actually intercepted, and changes none.",
    ),
    "ENDPOINT-NETWORK-ACCEPTED-COMPROMISED": _e(
        "A TLS handshake succeeded; a separate connection presented a compromised key.",
        "An opt-in connection to the host you named, plus inspection of the chain openssl reported.",
        "Update the OS store, browsers, runtimes and CLIs, then re-run.",
        "Separate connections may present different chains; effective acceptance is unproven.",
    ),
    "ENDPOINT-NETWORK-ACCEPTED-UNVERIFIED": _e(
        "A handshake succeeded but the chain could not be tied to an indicator.",
        "An opt-in connection succeeded; chain inspection was unavailable or inconclusive.",
        "Install openssl and re-run, and rely on the offline findings meanwhile.",
        "A proxy can substitute the certificate, so success alone proves nothing.",
    ),
    "ENDPOINT-NETWORK-REJECTED-COMPROMISED": _e(
        "One connection failed verification; a separate connection presented a compromised key.",
        "An opt-in connection failed verification and the chain matched an indicator.",
        "Nothing.",
        "The rejection reason is unattributed and cannot establish that this key is blocked.",
    ),
    "ENDPOINT-NETWORK-REJECTED-UNATTRIBUTED": _e(
        "A handshake was rejected, but the reason cannot be attributed to this incident.",
        "An opt-in connection failed and no indicator was observed in the chain.",
        "Treat as inconclusive; rely on the offline findings.",
        "Expiry, name mismatch, clock skew and proxies cause the same error.",
    ),
    "ENDPOINT-NETWORK-TEST-FAILED": _e(
        "The online test did not complete.",
        "DNS, routing or the host itself prevented a connection.",
        "Nothing; re-run later if you want the online signal.",
        "No conclusion follows from a connection that did not happen.",
    ),
    "ENDPOINT-NETWORK-TEST-INVALID": _e(
        "--network-test was given without a usable host.",
        "Argument parsing.",
        "Pass an explicit host name.",
        "The tool never picks a host for you.",
    ),
    "PROJECT-INVENTORY": _e(
        "The files that determine which TLS and CA components the project uses.",
        "File names were matched against data/rules/project-inventory.json.",
        "Use it to see which ecosystems need checking.",
        "It is an inventory, not a verdict.",
    ),
    "PROJECT-NO-MANIFEST": _e(
        "No dependency manifest or lock file was found in this directory.",
        "The whole walk produced no catalogued manifest name.",
        "Check the audit was pointed at the project root.",
        "Nothing about dependencies can be concluded.",
    ),
    "PROJECT-NO-LOCKFILE": _e(
        "A manifest exists without a lock file, so installed versions are undetermined.",
        "Manifest ecosystems were compared with the lock files present.",
        "Commit a lock file so CA-bundle versions can be audited.",
        "No version conclusion is possible for that ecosystem.",
    ),
    "PROJECT-SCAN-TRUNCATED": _e(
        "The file walk stopped at its configured limit.",
        "The number of files exceeded scan.max_files.",
        "Audit sub-directories separately or raise the limit.",
        "Files beyond the limit were never examined.",
    ),
    "PROJECT-DEPENDENCY-OUTDATED": _e(
        "A dependency that carries trust data is pinned below its fixed release.",
        "The lock file's pinned version was compared with the policy branch covering it.",
        "Update and commit the refreshed lock file; rebuild images and virtual environments.",
        "Lock file evidence only: the installed environment may differ.",
    ),
    "PROJECT-DEPENDENCY-CURRENT": _e(
        "A dependency is pinned at or above its fixed release.",
        "Lock file version plus policy comparison.",
        "Nothing.",
        "The environment actually installed may still differ from the lock file.",
    ),
    "PROJECT-DEPENDENCY-RANGE": _e(
        "The dependency is declared as a range, so the installed version is undetermined.",
        "A manifest range was found with no pinned version in a lock file.",
        "Inspect the lock file or the installed environment.",
        "A range can resolve either side of the fix.",
    ),
    "PROJECT-DEPENDENCY-BRANCH-UNKNOWN": _e(
        "The pinned version is on a branch the policy does not cover.",
        "No policy branch matched the pinned version.",
        "Check upstream release notes for that branch.",
        "No recorded fix is not the same as no problem.",
    ),
    "PROJECT-DEPENDENCY-UNCOMPARABLE": _e(
        "The pinned version could not be compared with the policy.",
        "Version parsing failed.",
        "Compare by hand.",
        "Nothing either way.",
    ),
    "PROJECT-WATCHLIST-DEPENDENCY": _e(
        "A dependency that makes its own trust decisions is present, with no fixed version recorded.",
        "The dependency name matched the policy watchlist.",
        "Confirm with upstream which release carries the updated trust data.",
        "Presence is not a defect; it marks a component the OS cannot fix for you.",
    ),
    "PROJECT-BUNDLE-COMPROMISED-SPKI": _e(
        "A CA bundle committed to this repository contains a compromised intermediate.",
        "Every committed .pem/.crt-style file was parsed and matched on SPKI SHA-256.",
        "Regenerate the bundle from an updated upstream source and rebuild what embedded it.",
        "It does not show the bundle was used in production - check what reads it.",
    ),
    "PROJECT-BUNDLE-CLEAN": _e(
        "Committed CA bundles carry none of the compromised intermediates.",
        "The same parse-and-compare over committed bundle files.",
        "Nothing.",
        "A bundle can still trust the root that signed a compromised intermediate.",
    ),
    "PROJECT-BUNDLE-RELATED-ROOT": _e(
        "A committed bundle contains one of the related roots. This is expected.",
        "Subject common names were compared with the related-root list.",
        "Nothing. Do not strip the root on the strength of this alone.",
        "It is not evidence of exposure.",
    ),
    "PROJECT-CONTAINER-NO-CA-REFRESH": _e(
        "A container build inherits its base image's CA bundle without refreshing it.",
        "Container files were read and matched against CA-refresh command patterns.",
        "Rebuild against a current base image, or add an explicit CA update step, then redeploy.",
        "A missing refresh step is not proof the image is affected; the base image may already be fixed.",
    ),
    "PROJECT-CONTAINER-DIGEST-PINNED": _e(
        "A base image is pinned by digest, which freezes its CA bundle.",
        "A FROM line contained an @sha256: digest.",
        "Update the digest to an image published after the fix.",
        "Digest pinning is good supply-chain practice; this is about keeping it current.",
    ),
    "PROJECT-CI-PINNED-RUNTIME": _e(
        "CI pins runtime versions or container images.",
        "CI definitions were read for version keys and image references.",
        "Compare each pin with the fixed versions in data/policies/.",
        "Context only; a pin is not a defect.",
    ),
    "PROJECT-TLS-SETTINGS-CLEAN": _e(
        "No weakened TLS setting was found in the scanned files.",
        "Every text file in scope was matched against the rules in data/rules/insecure-tls.json.",
        "Nothing.",
        "The rules are textual: a bypass written in a way no rule describes is not covered.",
    ),
    "PROJECT-SCAN-BUNDLE-COMPROMISED": _e(
        "The bundle named by --scan-bundle contains a compromised intermediate.",
        "The file was parsed and matched on SPKI SHA-256.",
        "Rebuild the bundle and redeploy whatever reads it.",
        "It says nothing about other bundles on the machine.",
    ),
    "PROJECT-SCAN-BUNDLE-CLEAN": _e(
        "The bundle named by --scan-bundle contains none of the compromised intermediates.",
        "The file was parsed and compared.",
        "Nothing.",
        "A clean bundle can still trust the signing root.",
    ),
    "PROJECT-SCAN-BUNDLE-UNREADABLE": _e(
        "The bundle named by --scan-bundle could not be read.",
        "The file could not be opened.",
        "Check the path and permissions.",
        "Nothing either way.",
    ),
}


def lookup(finding_id: str, data: Optional[DataBundle] = None) -> Optional[Explanation]:
    """Find an explanation, falling back to the textual ruleset in ``data/``."""
    key = finding_id.strip().upper()
    if key in CATALOG:
        return CATALOG[key]
    if data is not None and key.startswith("PROJECT-"):
        rule_id = key[len("PROJECT-") :]
        for rule in data.insecure_rules.get("rules", []):
            if str(rule.get("id", "")).upper() == rule_id:
                return Explanation(
                    meaning=str(rule.get("description", "")),
                    determined_by="Regular expression %s from data/rules/insecure-tls.json (status %s, confidence %s)."
                    % (rule.get("pattern"), rule.get("status"), rule.get("confidence")),
                    what_to_do=" ".join(rule.get("remediation", [])),
                    does_not_prove="A textual match describes configuration, not an observed interception.",
                )
    return None


def render(finding_id: str, explanation: Explanation) -> str:
    return "\n".join(
        [
            finding_id.strip().upper(),
            "",
            "What it means:",
            "  %s" % explanation.meaning,
            "",
            "How it was determined:",
            "  %s" % explanation.determined_by,
            "",
            "What to do:",
            "  %s" % explanation.what_to_do,
            "",
            "What it does not prove:",
            "  %s" % explanation.does_not_prove,
            "",
        ]
    )


def known_ids() -> List[str]:
    return sorted(CATALOG)
