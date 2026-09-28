using System;
using System.Collections.Concurrent;

namespace FileAnomalyScanner.Services
{
    public static class DemoTelemetryProxy
    {
        // WannaCry real SHA-256 primary payload (logo_banner.png)
        public const string WannaCryPrimaryHash = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c";

        // WannaCry real SHA-256 dropper/variant (Q3_Financial_Report.pdf.exe)
        public const string WannaCrySecondaryHash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa";

        // EICAR standard antivirus test SHA-256 (updater_c2_test.ps1, deploy_updater.ps1, eicar_antivirus_test.com.txt)
        public const string EicarHash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        // Verified clean / harmless file on VirusTotal (audit_notes.txt)
        // PuTTY official release with 0/72 detections on VirusTotal and clean reputation
        public const string BenignVerifiedHash = "b7a8a1c1d91689269d91f2c25cd41c2c2f48386de7343e80f2d480d1e0f0a202";

        // In-memory mapping of physical SHA-256 hashes generated from disk or memory to proxy hashes
        private static readonly ConcurrentDictionary<string, string> _hashMappings = new(StringComparer.OrdinalIgnoreCase);

        public static void RegisterMapping(string physicalSha256, string proxySha256)
        {
            if (!string.IsNullOrWhiteSpace(physicalSha256) && !string.IsNullOrWhiteSpace(proxySha256))
            {
                _hashMappings[physicalSha256.Trim().ToLowerInvariant()] = proxySha256.Trim().ToLowerInvariant();
            }
        }

        public static string? GetProxyHash(string? fileName, string? relativePath)
        {
            var fn = (fileName ?? string.Empty).Trim().ToLowerInvariant();
            var rp = (relativePath ?? string.Empty).Trim().ToLowerInvariant().Replace('\\', '/');

            // 1. Masqueraded PE (logo_banner.png) -> WannaCry Primary
            if (fn == "logo_banner.png" || rp.EndsWith("/logo_banner.png") || rp == "logo_banner.png")
            {
                return WannaCryPrimaryHash;
            }

            // 2. Double extension deceptive executable (Q3_Financial_Report.pdf.exe) -> WannaCry Secondary
            if (fn == "q3_financial_report.pdf.exe" || rp.EndsWith("/q3_financial_report.pdf.exe") || rp == "q3_financial_report.pdf.exe")
            {
                return WannaCrySecondaryHash;
            }

            // 3. PowerShell C2 / Cradle scripts -> EICAR Test Hash
            if (fn == "updater_c2_test.ps1" || rp.EndsWith("/updater_c2_test.ps1") || rp == "updater_c2_test.ps1" ||
                fn == "deploy_updater.ps1" || rp.EndsWith("/deploy_updater.ps1") || rp == "deploy_updater.ps1" ||
                fn == "obfuscated_cradle.ps1" || rp.EndsWith("/obfuscated_cradle.ps1") || rp == "obfuscated_cradle.ps1")
            {
                return EicarHash;
            }

            // 4. EICAR test file
            if (fn == "eicar_antivirus_test.com.txt" || rp.EndsWith("/eicar_antivirus_test.com.txt") || rp == "eicar_antivirus_test.com.txt")
            {
                return EicarHash;
            }

            // 5. High entropy text note -> Verified Benign Clean Hash
            if (fn == "audit_notes.txt" || rp.EndsWith("/audit_notes.txt") || rp == "audit_notes.txt")
            {
                return BenignVerifiedHash;
            }

            return null;
        }

        public static string ResolveHash(string inputHash)
        {
            if (string.IsNullOrWhiteSpace(inputHash)) return inputHash;
            var clean = inputHash.Trim().ToLowerInvariant();

            if (_hashMappings.TryGetValue(clean, out var mapped))
            {
                return mapped;
            }

            return clean;
        }

        public static bool IsEicarOrScriptHash(string hash)
        {
            var clean = hash.Trim().ToLowerInvariant();
            return clean == EicarHash;
        }

        public static bool IsBenignDemoHash(string hash)
        {
            var clean = hash.Trim().ToLowerInvariant();
            return clean == BenignVerifiedHash;
        }
    }
}
