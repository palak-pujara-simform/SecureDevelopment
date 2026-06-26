using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Models;
using System.Text.Json;

namespace OWASPDemo.Controllers;

public class A08_IntegrityController : Controller
{
    public IActionResult Index() => View(new DeserializeViewModel());

    // VULNERABLE: Deserializes without type validation — attacker can craft malicious payloads
    [HttpPost]
    public IActionResult VulnerableDeserialize(DeserializeViewModel vm)
    {
        vm.IsVulnerable = true;
        try
        {
            // VULNERABLE: Using dynamic/object deserialization with $type — enables gadget chains
            // Real-world: Newtonsoft.Json TypeNameHandling.All allows RCE via gadget chains
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var result = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(vm.JsonInput, options);

            if (result != null && result.TryGetValue("command", out var cmd))
            {
                // Simulated: in a real exploit this could execute arbitrary code
                vm.Output = $"[SIMULATED RCE] Would execute: {cmd.GetString()}\n\n" +
                            $"Parsed object: {JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true })}";
            }
            else
            {
                vm.Output = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            }
        }
        catch (Exception ex)
        {
            vm.Error = $"Deserialization error: {ex.Message}";
        }
        return View("Index", vm);
    }
}
