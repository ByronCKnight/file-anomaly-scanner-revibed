using System;
using System.Runtime.InteropServices;
using System.Text;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;
using Microsoft.Win32;

namespace FileAnomalyScanner.Services
{
    /// <summary>
    /// Offline virus detection through the Windows Antimalware Scan Interface (AMSI).
    /// File bytes are scanned in memory by whichever antivirus engine is registered on
    /// this machine (Microsoft Defender by default). No network calls or API keys needed.
    /// </summary>
    public sealed class LocalAntivirusService : ILocalAntivirusService, IDisposable
    {
        private const string AppName = "FileAnomalyScanner";
        private const string ProvidersKey = @"SOFTWARE\Microsoft\AMSI\Providers";

        // AMSI_RESULT values (amsi.h)
        private const int AmsiResultBlockedByAdminStart = 0x4000;
        private const int AmsiResultBlockedByAdminEnd = 0x4FFF;
        private const int AmsiResultDetected = 0x8000;

        private readonly ISecuritySettingsService _settingsService;
        private readonly object _lock = new();
        private IntPtr _context = IntPtr.Zero;
        private LocalAntivirusStatus? _status;

        public LocalAntivirusService(ISecuritySettingsService settingsService)
        {
            _settingsService = settingsService;
        }

        public bool IsEnabledAndAvailable()
        {
            return _settingsService.GetSettings().LocalAntivirusEnabled && GetStatus().Available;
        }

        public LocalAntivirusStatus GetStatus()
        {
            lock (_lock)
            {
                if (_status != null) return _status;

                var engine = ResolveProviderName();
                if (engine == null)
                {
                    _status = new LocalAntivirusStatus
                    {
                        Available = false,
                        Message = "No antivirus engine is registered with Windows AMSI on this machine."
                    };
                    return _status;
                }

                try
                {
                    int hr = AmsiInitialize(AppName, out _context);
                    _status = hr == 0
                        ? new LocalAntivirusStatus { Available = true, EngineName = engine, Message = $"{engine} ready via Windows AMSI (offline)." }
                        : new LocalAntivirusStatus { Available = false, EngineName = engine, Message = $"AMSI initialization failed (HRESULT 0x{hr:X8})." };
                }
                catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
                {
                    _status = new LocalAntivirusStatus { Available = false, Message = "Windows AMSI (amsi.dll) is not available on this system." };
                }

                return _status;
            }
        }

        public LocalAntivirusReport ScanBuffer(string contentName, byte[] content)
        {
            if (!_settingsService.GetSettings().LocalAntivirusEnabled)
            {
                return new LocalAntivirusReport { Status = "Disabled" };
            }

            var status = GetStatus();
            if (!status.Available)
            {
                return new LocalAntivirusReport { Status = "Unavailable", ErrorMessage = status.Message };
            }

            return ScanCore(contentName, content, status);
        }

        public TestApiResponse RunSelfTest()
        {
            var status = GetStatus();
            if (!status.Available)
            {
                return new TestApiResponse { Success = false, Message = status.Message };
            }

            // Built at runtime so this binary never contains the contiguous EICAR test signature.
            var eicar = Encoding.ASCII.GetBytes(string.Concat(
                @"X5O!P%@AP[4\PZX54(P^)7CC)7}$",
                "EICAR-STANDARD-ANTIVIRUS-",
                "TEST-FILE!$H+H*"));

            var report = ScanCore("eicar-selftest.com", eicar, status);
            if (report.Status == "Error")
            {
                return new TestApiResponse { Success = false, Message = report.ErrorMessage ?? "Local engine scan failed." };
            }

            return report.IsDetected
                ? new TestApiResponse
                {
                    Success = true,
                    Message = $"{status.EngineName} detected the EICAR test string. Offline scanning is working.",
                    Details = status.EngineName
                }
                : new TestApiResponse
                {
                    Success = false,
                    Message = $"{status.EngineName} responded but did not flag the EICAR test string. Real-time protection may be turned off.",
                    Details = status.EngineName
                };
        }

        private LocalAntivirusReport ScanCore(string contentName, byte[] content, LocalAntivirusStatus status)
        {
            var report = new LocalAntivirusReport { EngineName = status.EngineName };

            lock (_lock)
            {
                int hr = AmsiOpenSession(_context, out var session);
                if (hr != 0)
                {
                    report.Status = "Error";
                    report.ErrorMessage = $"AmsiOpenSession failed (HRESULT 0x{hr:X8}).";
                    return report;
                }

                try
                {
                    hr = AmsiScanBuffer(_context, content, (uint)content.Length, contentName, session, out int result);
                    if (hr != 0)
                    {
                        report.Status = "Error";
                        report.ErrorMessage = $"AmsiScanBuffer failed (HRESULT 0x{hr:X8}).";
                        return report;
                    }

                    report.ResultCode = result;
                    if (result >= AmsiResultDetected)
                    {
                        report.Status = "Detected";
                        report.IsDetected = true;
                    }
                    else if (result >= AmsiResultBlockedByAdminStart && result <= AmsiResultBlockedByAdminEnd)
                    {
                        report.Status = "BlockedByPolicy";
                        report.IsDetected = true;
                    }
                    else
                    {
                        report.Status = "Clean";
                    }
                }
                finally
                {
                    AmsiCloseSession(_context, session);
                }
            }

            return report;
        }

        /// <summary>
        /// Returns a friendly name for the first registered AMSI provider, or null when none exist.
        /// </summary>
        private static string? ResolveProviderName()
        {
            try
            {
                using var providers = Registry.LocalMachine.OpenSubKey(ProvidersKey);
                var clsids = providers?.GetSubKeyNames();
                if (clsids == null || clsids.Length == 0) return null;

                using var clsidKey = Registry.ClassesRoot.OpenSubKey($@"CLSID\{clsids[0]}");
                var rawName = clsidKey?.GetValue(null) as string;
                if (string.IsNullOrWhiteSpace(rawName)) return "Registered AMSI Antivirus";

                if (rawName.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase))
                    return "Microsoft Defender Antivirus";

                return rawName
                    .Replace("IOfficeAntiVirus implementation", "", StringComparison.OrdinalIgnoreCase)
                    .Replace("IAmsiProvider", "", StringComparison.OrdinalIgnoreCase)
                    .Trim();
            }
            catch
            {
                return null;
            }
        }

        public void Dispose()
        {
            lock (_lock)
            {
                if (_context != IntPtr.Zero)
                {
                    AmsiUninitialize(_context);
                    _context = IntPtr.Zero;
                }
            }
        }

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll")]
        private static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("amsi.dll")]
        private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        [DllImport("amsi.dll")]
        private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        private static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr session, out int result);
    }
}
