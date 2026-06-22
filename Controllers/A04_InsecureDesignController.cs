using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Data;
using OWASPDemo.Models;
using System.Security.Cryptography;

namespace OWASPDemo.Controllers;

public class A04_InsecureDesignController : Controller
{
    private readonly AppDbContext _db;
    private static readonly Dictionary<string, (int Count, DateTime Window)> _resetTracker = new();

    public A04_InsecureDesignController(AppDbContext db) => _db = db;

    public IActionResult Index() => View(new PasswordResetViewModel());

    // VULNERABLE: No rate limiting — attacker can flood password reset emails
    [HttpPost]
    public IActionResult VulnerableReset(PasswordResetViewModel vm)
    {
        vm.IsVulnerable = true;
        var user = _db.Users.FirstOrDefault(u => u.Email == vm.Email);
        if (user != null)
        {
            // No rate limiting — this endpoint can be spammed
            user.PasswordResetToken = Guid.NewGuid().ToString("N");
            user.ResetTokenExpiry = DateTime.UtcNow.AddDays(30); // Tokens never expire practically
            _db.SaveChanges();
            vm.Success = true;
            vm.Message = $"Reset token generated: {user.PasswordResetToken} (no rate limit, token valid 30 days!)";
        }
        else
        {
            vm.Message = "Email not found."; // Reveals whether email exists — user enumeration
        }
        return View("Index", vm);
    }

    // SECURE: Rate limited, short-lived token, no user enumeration
    [HttpPost]
    public IActionResult SecureReset(PasswordResetViewModel vm)
    {
        vm.IsVulnerable = false;

        // Rate limit: max 3 requests per 15 minutes per email
        var key = vm.Email.ToLower();
        if (_resetTracker.TryGetValue(key, out var entry))
        {
            if (DateTime.UtcNow - entry.Window < TimeSpan.FromMinutes(15))
            {
                if (entry.Count >= 3)
                {
                    vm.Message = "Too many requests. Please try again in 15 minutes.";
                    return View("Index", vm);
                }
                _resetTracker[key] = (entry.Count + 1, entry.Window);
            }
            else
            {
                _resetTracker[key] = (1, DateTime.UtcNow);
            }
        }
        else
        {
            _resetTracker[key] = (1, DateTime.UtcNow);
        }

        var user = _db.Users.FirstOrDefault(u => u.Email == vm.Email);
        if (user != null)
        {
            user.PasswordResetToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            user.ResetTokenExpiry = DateTime.UtcNow.AddMinutes(15); // Short-lived token
            _db.SaveChanges();
        }

        // Always return same message — prevents user enumeration
        vm.Success = true;
        vm.Message = "If that email exists, a reset link has been sent. Check your inbox.";
        return View("Index", vm);
    }
}
