using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Interfaces
{
    public interface ILocalAntivirusService
    {
        bool IsEnabledAndAvailable();
        LocalAntivirusStatus GetStatus();
        LocalAntivirusReport ScanBuffer(string contentName, byte[] content);
        TestApiResponse RunSelfTest();
    }
}
