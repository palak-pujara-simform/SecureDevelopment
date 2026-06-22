using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Models;

namespace OWASPDemo.Controllers;

public class A10_SSRFController : Controller
{
    private readonly HttpClient _http;
    private static readonly HashSet<string> _allowedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "api.github.com",
        "httpbin.org",
        "jsonplaceholder.typicode.com"
    };

    public A10_SSRFController(IHttpClientFactory factory)
    {
        _http = factory.CreateClient();
        _http.Timeout = TimeSpan.FromSeconds(5);
    }

    public IActionResult Index() => View(new SSRFViewModel());

    // VULNERABLE: Fetches any URL the user provides — internal services accessible
    [HttpPost]
    public async Task<IActionResult> VulnerableFetch(SSRFViewModel vm)
    {
        vm.IsVulnerable = true;
        try
        {
            // VULNERABLE: No URL validation — try http://169.254.169.254/latest/meta-data/ (AWS metadata)
            // or http://localhost/admin, http://internal-db:5432
            var response = await _http.GetAsync(vm.Url);
            vm.StatusCode = (int)response.StatusCode;
            vm.Response = await response.Content.ReadAsStringAsync();
            if (vm.Response.Length > 2000) vm.Response = vm.Response[..2000] + "\n... [truncated]";
        }
        catch (Exception ex)
        {
            vm.Error = $"Request error: {ex.Message}";
        }
        return View("Index", vm);
    }

    // SECURE: Allow-list validation before any outbound request
    [HttpPost]
    public async Task<IActionResult> SecureFetch(SSRFViewModel vm)
    {
        vm.IsVulnerable = false;
        try
        {
            if (!Uri.TryCreate(vm.Url, UriKind.Absolute, out var uri))
            {
                vm.Error = "Blocked: Invalid URL format.";
                return View("Index", vm);
            }

            // Only HTTPS allowed
            if (uri.Scheme != "https")
            {
                vm.Error = "Blocked: Only HTTPS URLs are permitted.";
                return View("Index", vm);
            }

            // Host must be on the allow-list
            if (!_allowedHosts.Contains(uri.Host))
            {
                vm.Error = $"Blocked: '{uri.Host}' is not on the allowed host list.\n" +
                           $"Allowed: {string.Join(", ", _allowedHosts)}";
                return View("Index", vm);
            }

            var response = await _http.GetAsync(uri);
            vm.StatusCode = (int)response.StatusCode;
            vm.Response = await response.Content.ReadAsStringAsync();
            if (vm.Response.Length > 2000) vm.Response = vm.Response[..2000] + "\n... [truncated]";
        }
        catch (Exception ex)
        {
            vm.Error = $"Request error: {ex.Message}";
        }
        return View("Index", vm);
    }
}
