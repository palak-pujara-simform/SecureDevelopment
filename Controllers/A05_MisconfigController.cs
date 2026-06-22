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

    // SECURE: Generic error shown to user, detail logged internally only
    public IActionResult SecureError()
    {
        try
        {
            throw new InvalidOperationException("Connection failed to internal-db...");
        }
        catch (Exception ex)
        {
            // SECURE: Log internally (not shown to user)
            Console.Error.WriteLine($"[INTERNAL LOG] {ex}");

            ViewBag.ErrorDetail = "An unexpected error occurred. Our team has been notified. Reference: ERR-20240615-001";
            ViewBag.IsVulnerable = false;
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

    // SECURE: Admin panel checks role
    public IActionResult SecureAdmin()
    {
        // Simulated: check role from session
        var role = HttpContext.Session.GetString("Role") ?? "guest";
        ViewBag.IsVulnerable = false;

        if (role != "admin")
        {
            ViewBag.Error = "403 Forbidden: Admin access required.";
            return View("AdminPanel");
        }

        ViewBag.Users = _db.Users.ToList();
        return View("AdminPanel");
    }

    public IActionResult SetAdminSession()
    {
        HttpContext.Session.SetString("Role", "admin");
        return RedirectToAction("SecureAdmin");
    }
}
