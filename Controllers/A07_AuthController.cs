using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Data;
using OWASPDemo.Models;

namespace OWASPDemo.Controllers;

public class A07_AuthController : Controller
{
    private readonly AppDbContext _db;

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
}
