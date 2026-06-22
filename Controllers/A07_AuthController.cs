using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Data;
using OWASPDemo.Models;

namespace OWASPDemo.Controllers;

public class A07_AuthController : Controller
{
    private readonly AppDbContext _db;
    private const int MaxLoginAttempts = 5;
    private const int LockoutMinutes = 15;

    public A07_AuthController(AppDbContext db) => _db = db;

    public IActionResult Index() => View(new LoginViewModel());

    // VULNERABLE: No lockout, no BCrypt, plaintext password comparison, weak session
    [HttpPost]
    public IActionResult VulnerableLogin(LoginViewModel vm)
    {
        vm.IsVulnerable = true;
        var user = _db.Users.FirstOrDefault(u => u.Username == vm.Username);

        if (user != null && user.PasswordPlain == vm.Password)
        {
            // VULNERABLE: Predictable session — just sets username in session without regeneration
            HttpContext.Session.SetString("VulnUser", user.Username);
            HttpContext.Session.SetInt32("VulnUserId", user.Id);
            // No lockout tracking, session fixation possible, no 2FA
            vm.Success = true;
            vm.LoggedInUser = user;
            vm.Message = $"Logged in as {user.Username} (Role: {user.Role}) — no lockout, plaintext comparison!";
        }
        else
        {
            // VULNERABLE: Reveals whether username exists
            vm.Message = user == null
                ? "Username does not exist."
                : "Wrong password. Try again.";
        }
        return View("Index", vm);
    }

    // SECURE: BCrypt, account lockout, generic error message
    [HttpPost]
    public IActionResult SecureLogin(LoginViewModel vm)
    {
        vm.IsVulnerable = false;
        var user = _db.Users.FirstOrDefault(u => u.Username == vm.Username);

        // Check account lockout first
        if (user != null && user.LockedUntil.HasValue && user.LockedUntil > DateTime.UtcNow)
        {
            var remaining = (int)(user.LockedUntil.Value - DateTime.UtcNow).TotalMinutes + 1;
            vm.Message = $"Account locked. Try again in {remaining} minute(s).";
            return View("Index", vm);
        }

        if (user != null && BCrypt.Net.BCrypt.Verify(vm.Password, user.PasswordHash))
        {
            // Reset login attempts on success
            user.LoginAttempts = 0;
            user.LockedUntil = null;
            _db.SaveChanges();

            // Regenerate session to prevent session fixation
            HttpContext.Session.Clear();
            HttpContext.Session.SetString("SecureUser", user.Username);
            HttpContext.Session.SetInt32("SecureUserId", user.Id);
            HttpContext.Session.SetString("Role", user.Role);

            vm.Success = true;
            vm.LoggedInUser = user;
            vm.Message = $"Secure login successful as {user.Username}.";
        }
        else
        {
            if (user != null)
            {
                user.LoginAttempts++;
                if (user.LoginAttempts >= MaxLoginAttempts)
                {
                    user.LockedUntil = DateTime.UtcNow.AddMinutes(LockoutMinutes);
                    vm.Message = $"Too many failed attempts. Account locked for {LockoutMinutes} minutes.";
                }
                else
                {
                    vm.Message = $"Invalid credentials. {MaxLoginAttempts - user.LoginAttempts} attempt(s) remaining.";
                }
                _db.SaveChanges();
            }
            else
            {
                // Generic message — no user enumeration
                vm.Message = "Invalid credentials.";
            }
        }
        return View("Index", vm);
    }

    public IActionResult ResetLockout()
    {
        foreach (var u in _db.Users)
        {
            u.LoginAttempts = 0;
            u.LockedUntil = null;
        }
        _db.SaveChanges();
        return RedirectToAction("Index");
    }
}
