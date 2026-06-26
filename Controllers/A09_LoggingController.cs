using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Data;
using OWASPDemo.Models;

namespace OWASPDemo.Controllers;

public class A09_LoggingController : Controller
{
    private readonly AppDbContext _db;
    private static readonly List<string> _vulnerableLogs = new();

    public A09_LoggingController(AppDbContext db) => _db = db;

    public IActionResult Index()
    {
        var vm = new LoggingViewModel
        {
            RecentLogs = _db.AuditLogs.OrderByDescending(l => l.Timestamp).Take(20).ToList()
        };
        return View(vm);
    }

    // VULNERABLE: Logs sensitive data, no audit trail for security events
    [HttpPost]
    public IActionResult VulnerableLogin(LoggingViewModel vm)
    {
        vm.IsVulnerable = true;
        var user = _db.Users.FirstOrDefault(u => u.Username == vm.Username);

        // VULNERABLE: Logs plaintext password and PII
        var logEntry = $"[{DateTime.UtcNow:O}] LOGIN ATTEMPT - Username: {vm.Username}, " +
                       $"Password: {vm.Password}, IP: {HttpContext.Connection.RemoteIpAddress}, " +
                       $"SSN: {user?.SSN}, CreditCard: {user?.CreditCard}";
        _vulnerableLogs.Add(logEntry);

        bool success = user?.PasswordPlain == vm.Password;
        vm.Success = success;
        // No failed-login audit, no brute-force detection
        vm.LogOutput = string.Join("\n", _vulnerableLogs.TakeLast(5));
        vm.Message = success ? $"Login OK (password logged!)" : "Failed (all details logged anyway)";
        vm.RecentLogs = _db.AuditLogs.OrderByDescending(l => l.Timestamp).Take(10).ToList();
        return View("Index", vm);
    }

    public IActionResult ClearLogs()
    {
        _vulnerableLogs.Clear();
        _db.AuditLogs.RemoveRange(_db.AuditLogs);
        _db.SaveChanges();
        return RedirectToAction("Index");
    }
}
