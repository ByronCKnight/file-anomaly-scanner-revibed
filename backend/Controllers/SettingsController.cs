using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using FileAnomalyScanner.Interfaces;
using FileAnomalyScanner.Models;

namespace FileAnomalyScanner.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SettingsController : ControllerBase
    {
        private readonly ISecuritySettingsService _settingsService;
        private readonly IVirusTotalService _virusTotalService;
        private readonly ISafeBrowsingService _safeBrowsingService;
        private readonly ILocalAntivirusService _localAntivirusService;

        public SettingsController(
            ISecuritySettingsService settingsService,
            IVirusTotalService virusTotalService,
            ISafeBrowsingService safeBrowsingService,
            ILocalAntivirusService localAntivirusService)
        {
            _settingsService = settingsService;
            _virusTotalService = virusTotalService;
            _safeBrowsingService = safeBrowsingService;
            _localAntivirusService = localAntivirusService;
        }

        [HttpGet]
        public IActionResult GetSettings()
        {
            return Ok(BuildSettingsDto());
        }

        [HttpPost]
        public async Task<IActionResult> UpdateSettings([FromBody] UpdateSecuritySettingsRequest request)
        {
            if (request == null)
            {
                return BadRequest(new { message = "Empty payload received." });
            }

            await _settingsService.UpdateSettingsAsync(request);
            var updated = BuildSettingsDto();
            return Ok(new
            {
                success = true,
                message = "Threat intelligence settings successfully updated.",
                settings = updated
            });
        }

        [HttpPost("test-virustotal")]
        public async Task<ActionResult<TestApiResponse>> TestVirusTotal(
            [FromBody] TestApiRequest? req,
            CancellationToken cancellationToken = default)
        {
            var result = await _virusTotalService.TestConnectionAsync(req?.ApiKey, cancellationToken);
            return Ok(result);
        }

        [HttpPost("test-safebrowsing")]
        public async Task<ActionResult<TestApiResponse>> TestSafeBrowsing(
            [FromBody] TestApiRequest? req,
            CancellationToken cancellationToken = default)
        {
            var result = await _safeBrowsingService.TestConnectionAsync(req?.ApiKey, cancellationToken);
            return Ok(result);
        }

        [HttpPost("test-local-av")]
        public ActionResult<TestApiResponse> TestLocalAntivirus()
        {
            return Ok(_localAntivirusService.RunSelfTest());
        }

        private SecuritySettingsDto BuildSettingsDto()
        {
            var dto = _settingsService.GetSettingsDto();
            var avStatus = _localAntivirusService.GetStatus();
            dto.LocalAntivirusAvailable = avStatus.Available;
            dto.LocalAntivirusEngine = avStatus.EngineName;
            dto.LocalAntivirusMessage = avStatus.Message;
            return dto;
        }
    }
}
