using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Models;

namespace OWASPDemo.Controllers;

public class A06_ComponentsController : Controller
{
    public IActionResult Index()
    {
        var vm = new ComponentsViewModel
        {
            VulnerablePackages = new List<VulnerablePackage>
            {
                new() {
                    Name = "Newtonsoft.Json",
                    InstalledVersion = "9.0.1",
                    SafeVersion = "13.0.3",
                    CVE = "CVE-2024-21907",
                    Severity = "High",
                    Description = "Improper handling of exceptional conditions allows DoS via specially crafted JSON."
                },
                new() {
                    Name = "System.Text.Encodings.Web",
                    InstalledVersion = "4.5.0",
                    SafeVersion = "8.0.0",
                    CVE = "CVE-2021-26701",
                    Severity = "Critical",
                    Description = "Remote code execution vulnerability in .NET Core and .NET 5."
                },
                new() {
                    Name = "Microsoft.AspNetCore.Http",
                    InstalledVersion = "2.1.0",
                    SafeVersion = "8.0.0",
                    CVE = "CVE-2019-0815",
                    Severity = "Medium",
                    Description = "Denial of service when processing specially crafted HTTP/2 requests."
                },
                new() {
                    Name = "log4net",
                    InstalledVersion = "2.0.8",
                    SafeVersion = "2.0.15",
                    CVE = "CVE-2018-1285",
                    Severity = "Critical",
                    Description = "XML external entity injection (Log4Shell equivalent for .NET)."
                },
                new() {
                    Name = "SolarWinds.Orion.Core",
                    InstalledVersion = "2020.2.0",
                    SafeVersion = "2020.2.6",
                    CVE = "CVE-2020-10148",
                    Severity = "Critical",
                    Description = "SolarWinds supply-chain backdoor — SUNBURST malware injected via update."
                }
            }
        };
        return View(vm);
    }
}
