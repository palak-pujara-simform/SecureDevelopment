using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Data;
using OWASPDemo.Models;

namespace OWASPDemo.Controllers;

public class A04_InsecureDesignController : Controller
{
    private readonly AppDbContext _db;

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
}
