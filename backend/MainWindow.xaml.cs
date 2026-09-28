using System;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;
using FileAnomalyScanner.Services;

namespace FileAnomalyScanner
{
    public partial class MainWindow : Window
    {
        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

        public MainWindow()
        {
            InitializeComponent();
            this.WindowStyle = WindowStyle.SingleBorderWindow;
            this.ResizeMode = ResizeMode.CanResize;
            AdjustWindowToWorkArea();
            Loaded += MainWindow_Loaded;
            SourceInitialized += MainWindow_SourceInitialized;
        }

        private void MainWindow_SourceInitialized(object? sender, EventArgs e)
        {
            // Sync initial title bar to dark mode on handle creation
            SetWindowDarkMode(true);
        }

        public void SetWindowDarkMode(bool isDark)
        {
            try
            {
                var helper = new WindowInteropHelper(this);
                var hwnd = helper.Handle;
                if (hwnd == IntPtr.Zero) return;

                int useImmersiveDarkMode = isDark ? 1 : 0;
                int hr = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useImmersiveDarkMode, sizeof(int));
                if (hr != 0)
                {
                    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, ref useImmersiveDarkMode, sizeof(int));
                }
            }
            catch
            {
                // DWM immersive dark mode attribute requires Windows 10 build 17763+ / Windows 11
            }
        }

        private void AdjustWindowToWorkArea()
        {
            var workArea = SystemParameters.WorkArea;

            // Constrain maximum size so it never spills outside current display
            this.MaxWidth = workArea.Width;
            this.MaxHeight = workArea.Height;

            if (this.Height > workArea.Height * 0.92)
            {
                this.Height = Math.Max(this.MinHeight, workArea.Height * 0.88);
            }
            if (this.Width > workArea.Width * 0.95)
            {
                this.Width = Math.Max(this.MinWidth, workArea.Width * 0.92);
            }

            // Ensure window title bar is never pushed off-screen (Top >= workArea.Top)
            this.Left = Math.Max(workArea.Left, workArea.Left + (workArea.Width - this.Width) / 2);
            this.Top = Math.Max(workArea.Top, workArea.Top + (workArea.Height - this.Height) / 2);
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                SetWindowDarkMode(true);
                await ScannerWebView.EnsureCoreWebView2Async();

                // Listen for theme change messages from the React web app
                ScannerWebView.CoreWebView2.WebMessageReceived += (s, args) =>
                {
                    try
                    {
                        var json = args.TryGetWebMessageAsString();
                        if (string.IsNullOrWhiteSpace(json))
                        {
                            json = args.WebMessageAsJson;
                        }
                        if (string.IsNullOrWhiteSpace(json)) return;

                        using var doc = JsonDocument.Parse(json);
                        if (doc.RootElement.TryGetProperty("type", out var typeProp) && typeProp.GetString() == "THEME_CHANGED")
                        {
                            if (doc.RootElement.TryGetProperty("theme", out var themeProp))
                            {
                                var theme = themeProp.GetString();
                                Dispatcher.Invoke(() => SetWindowDarkMode(theme == "dark"));
                            }
                        }
                    }
                    catch
                    {
                        // Ignore malformed web messages
                    }
                };

                // Prevent stale WebView2 disk caching across application updates
                await ScannerWebView.CoreWebView2.Profile.ClearBrowsingDataAsync();

                ScannerWebView.Source = new Uri(DesktopHost.BaseUrl);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Error initializing WebView2 browser engine:\n{ex.Message}\n\nPlease ensure Microsoft Edge WebView2 Runtime is installed.",
                    "WebView2 Initialization Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }
}
