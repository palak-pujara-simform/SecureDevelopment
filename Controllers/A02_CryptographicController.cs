using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Data;
using OWASPDemo.Models;
using System.Security.Cryptography;
using System.Text;

namespace OWASPDemo.Controllers;

public class A02_CryptographicController : Controller
{
    private readonly AppDbContext _db;
    private readonly IConfiguration _config;

    public A02_CryptographicController(AppDbContext db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    public IActionResult Index() => View(new CryptoViewModel());

    // VULNERABLE: MD5 hashing — reversible via rainbow tables
    [HttpPost]
    public IActionResult VulnerableHash(CryptoViewModel vm)
    {
        if (!string.IsNullOrEmpty(vm.Password))
        {
            using var md5 = MD5.Create();
            var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(vm.Password));
            vm.Hash = Convert.ToHexString(bytes).ToLower();
            vm.Algorithm = "MD5";
            vm.IsVulnerable = true;
            vm.Message = "MD5 is a broken algorithm — rainbow tables can reverse this hash instantly.";
        }
        return View("Index", vm);
    }

    // Show hardcoded secrets from appsettings — exposed sensitive data
    public IActionResult ShowSecrets()
    {
        var secrets = new Dictionary<string, string?>
        {
            ["SecretKey"] = _config["AppSettings:SecretKey"],
            ["AdminPassword"] = _config["AppSettings:AdminPassword"],
            ["ApiToken"] = _config["AppSettings:ApiToken"],
            ["DatabasePassword"] = _config["AppSettings:DatabasePassword"]
        };
        ViewBag.Secrets = secrets;
        ViewBag.Users = _db.Users.ToList();
        return View("Secrets");
    }
}
