# SDS Rapid Check: CISA Known Exploited Vulnerabilities

Lists recent CISA Known Exploited Vulnerabilities and highlights vendor or product names you specify.

## About SDS

**Security, AI & Systems Engineering**

Secure Data Solutions helps businesses strengthen their security and put AI to work. We engineer the systems and workflows that reduce repetitive work, help teams understand and respond to threats, and turn security findings into verified improvements.

We publish SDS Rapid Checks as free, focused tools to help the community investigate specific risks and understand what needs attention. Each check states what it looks for, how to run it, and what its results can and cannot tell you.

[Discuss your project](https://sdsitgroup.com/contact) · [Explore our services](https://sdsitgroup.com/services/)

Ran this and found something, or not sure what you're looking at? [Contact us](https://sdsitgroup.com/contact). We're happy to talk it through, and when it's urgent, we pick up.

Read the script first. [kev_check.py](kev_check.py)

Requires Python 3.8 or later.

## macOS

```sh
base='https://github.com/SecureDataSolutions/sds-rapid-check-cisa-kev/releases/latest/download'
curl -fsSLo kev_check.py "$base/kev_check.py" &&
curl -fsSLo SHA256SUMS "$base/SHA256SUMS" &&
shasum -a 256 -c SHA256SUMS &&
python3 -I -B -S kev_check.py --days 7 --vendors cisco vmware
```

Change the vendor words and look-back window as needed. The default window covers seven calendar days including today.

### Offline

While online, save the [CISA KEV JSON catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) as `kev.json` on local disk. Once offline, run the check against that copy.

```sh
python3 -I -B -S kev_check.py --file kev.json --days 7 --vendors cisco vmware
```

## Linux

```sh
base='https://github.com/SecureDataSolutions/sds-rapid-check-cisa-kev/releases/latest/download'
curl -fsSLo kev_check.py "$base/kev_check.py" &&
curl -fsSLo SHA256SUMS "$base/SHA256SUMS" &&
sha256sum -c SHA256SUMS &&
python3 -I -B -S kev_check.py --days 7 --vendors cisco vmware
```

Change the vendor words and look-back window as needed. The default window covers seven calendar days including today.

### Offline

While online, save the [CISA KEV JSON catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) as `kev.json` on local disk. Once offline, run the check against that copy.

```sh
python3 -I -B -S kev_check.py --file kev.json --days 7 --vendors cisco vmware
```

## Windows (PowerShell)

```powershell
& {
$ErrorActionPreference = 'Stop'
$base = 'https://github.com/SecureDataSolutions/sds-rapid-check-cisa-kev/releases/latest/download'
Invoke-WebRequest "$base/kev_check.py" -OutFile .\kev_check.py
Invoke-WebRequest "$base/SHA256SUMS" -OutFile .\SHA256SUMS
$entries = @(Get-Content .\SHA256SUMS | Where-Object { $_ -match '^([0-9a-fA-F]{64})  kev_check\.py$' })
if ($entries.Count -ne 1) { throw 'Expected one SHA-256 entry for kev_check.py' }
$expected = $entries[0].Substring(0, 64).ToLowerInvariant()
$actual = (Get-FileHash .\kev_check.py -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'kev_check.py SHA-256 verification failed' }
py -3 -I -B -S .\kev_check.py --days 7 --vendors cisco vmware
}
```

### Offline

In a browser, download the [CISA KEV JSON catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) and save it as `kev.json`. Then run:

```powershell
py -3 -I -B -S .\kev_check.py --file .\kev.json --days 7 --vendors cisco vmware
```

## What a result means

The check shows catalog entries added during the selected date window. Vendor matching only searches CISA's vendor and product names. An empty result does not show whether your systems are affected or compromised.

No finding is not proof of no compromise.

## Sources

- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [CISA KEV data mirror](https://github.com/cisagov/kev-data)

## Want the full check?

The AI Coding Tool Check covers up to five developer machines and one build pipeline. The fixed price is $1,250 for the first three teams.

[Discuss your project](https://sdsitgroup.com/contact) · [Explore our services](https://sdsitgroup.com/services/)

Run only on systems you own or are authorized to check. Licensed under the MIT License.
