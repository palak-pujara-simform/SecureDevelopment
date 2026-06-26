using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Models;

namespace OWASPDemo.Controllers;

public class A10_SSRFController : Controller
{
    private readonly HttpClient _http;

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
}
