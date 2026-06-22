using Microsoft.AspNetCore.Mvc;
using OWASPDemo.Data;
using OWASPDemo.Models;

namespace OWASPDemo.Controllers;

public class A01_BrokenAccessController : Controller
{
    private readonly AppDbContext _db;

    public A01_BrokenAccessController(AppDbContext db) => _db = db;

    public IActionResult Index() => View();

    // VULNERABLE: No ownership check — any user can read any profile by changing ?id=
    public IActionResult VulnerableProfile(int id = 1)
    {
        var user = _db.Users.Find(id);
        return View("Profile", new AccessControlViewModel
        {
            UserId = id,
            RequestedUser = user,
            IsVulnerable = true,
            CurrentUserId = 1,
            CurrentUsername = "alice",
            Error = user == null ? "User not found." : null
        });
    }

    // SECURE: Ownership enforced — user can only view their own profile (or admin can view all)
    public IActionResult SecureProfile(int id = 1)
    {
        const int currentUserId = 1;
        const string currentUsername = "alice";

        var currentUser = _db.Users.Find(currentUserId);
        if (id != currentUserId && currentUser?.Role != "admin")
        {
            return View("Profile", new AccessControlViewModel
            {
                UserId = id,
                IsVulnerable = false,
                CurrentUserId = currentUserId,
                CurrentUsername = currentUsername,
                Error = "403 Forbidden: You can only view your own profile."
            });
        }

        var user = _db.Users.Find(id);
        return View("Profile", new AccessControlViewModel
        {
            UserId = id,
            RequestedUser = user,
            IsVulnerable = false,
            CurrentUserId = currentUserId,
            CurrentUsername = currentUsername,
            Error = user == null ? "User not found." : null
        });
    }
}
