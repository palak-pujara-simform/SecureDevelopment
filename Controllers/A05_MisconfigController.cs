using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Data;
using OWASPDemo.Models;

namespace OWASPDemo.Controllers;

public class A05_MisconfigController : Controller
{
    private readonly AppDbContext _db;

    public A05_MisconfigController(AppDbContext db) => _db = db;

    public IActionResult Index() => View();

    // VULNERABLE: Returns full exception detail to client
    public IActionResult VulnerableError()
    {
        try
        {
            // Simulate an internal failure
            var connStr = "Server=internal-db;Database=PayrollDB;User=sa;Password=Str0ngP@ss!";
            throw new InvalidOperationException(
                $"Connection failed to {connStr}. Stack trace reveals internal architecture.");
        }
        catch (Exception ex)
        {
            // VULNERABLE: Exposes stack trace, connection strings, internal paths
            ViewBag.ErrorDetail = ex.ToString();
            ViewBag.IsVulnerable = true;
            return View("ErrorDemo");
        }
    }

    // VULNERABLE: Admin panel accessible without authentication
    public IActionResult VulnerableAdmin()
    {
        ViewBag.IsVulnerable = true;
        ViewBag.Users = _db.Users.ToList();
        return View("AdminPanel");
    }
}
