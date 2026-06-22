using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using OWASPDemo.Data;
using OWASPDemo.Models;
using System.Diagnostics;

namespace OWASPDemo.Controllers;

public class A03_InjectionController : Controller
{
    private readonly AppDbContext _db;
    private readonly IConfiguration _config;

    // In-memory storage for XSS demo — intentionally shared
    private static string _vulnerableXssComment = string.Empty;
    private static string _safeXssComment = string.Empty;

    public A03_InjectionController(AppDbContext db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    public IActionResult Index() => View();

    // ── SQL INJECTION ──────────────────────────────────────────────────────────

    public IActionResult SqlInjection() => View(new SqlSearchViewModel());

    // VULNERABLE: String concatenation in SQL query
    [HttpPost]
    public IActionResult SqlVulnerable(SqlSearchViewModel vm)
    {
        vm.IsVulnerable = true;
        try
        {
            var connStr = _config.GetConnectionString("DefaultConnection");
            using var conn = new SqliteConnection(connStr);
            conn.Open();

            // VULNERABLE: Direct string interpolation — try: ' OR '1'='1
            vm.SqlQuery = $"SELECT * FROM Products WHERE Name LIKE '%{vm.SearchTerm}%'";

            using var cmd = conn.CreateCommand();
            cmd.CommandText = vm.SqlQuery;
            vm.Results = new List<Product>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                vm.Results.Add(new Product
                {
                    Id = reader.GetInt32(0), Name = reader.GetString(1),
                    Description = reader.GetString(2), Price = reader.GetDecimal(3),
                    Category = reader.GetString(4)
                });
        }
        catch (Exception ex) { vm.Error = ex.Message; }
        return View("SqlInjection", vm);
    }

    // SECURE: Parameterized query
    [HttpPost]
    public IActionResult SqlSecure(SqlSearchViewModel vm)
    {
        vm.IsVulnerable = false;
        try
        {
            var connStr = _config.GetConnectionString("DefaultConnection");
            using var conn = new SqliteConnection(connStr);
            conn.Open();

            vm.SqlQuery = "SELECT * FROM Products WHERE Name LIKE @term";
            using var cmd = conn.CreateCommand();
            cmd.CommandText = vm.SqlQuery;
            cmd.Parameters.AddWithValue("@term", $"%{vm.SearchTerm}%");
            vm.Results = new List<Product>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                vm.Results.Add(new Product
                {
                    Id = reader.GetInt32(0), Name = reader.GetString(1),
                    Description = reader.GetString(2), Price = reader.GetDecimal(3),
                    Category = reader.GetString(4)
                });
        }
        catch (Exception ex) { vm.Error = ex.Message; }
        return View("SqlInjection", vm);
    }

    // ── XSS ───────────────────────────────────────────────────────────────────

    public IActionResult XSS() => View(new XssViewModel { StoredComment = _vulnerableXssComment });

    // VULNERABLE: Stores and renders raw HTML/JS — try: <script>alert('XSS')</script>
    [HttpPost]
    public IActionResult XssVulnerable(XssViewModel vm)
    {
        _vulnerableXssComment = vm.Comment;
        vm.StoredComment = _vulnerableXssComment;
        vm.IsVulnerable = true;
        vm.Message = "Comment stored without encoding — injected HTML/JS will execute in browser.";
        return View("XSS", vm);
    }

    // SECURE: HTML-encodes output before rendering
    [HttpPost]
    public IActionResult XssSecure(XssViewModel vm)
    {
        _safeXssComment = System.Net.WebUtility.HtmlEncode(vm.Comment);
        vm.StoredComment = _safeXssComment;
        vm.IsVulnerable = false;
        vm.Message = "Comment HTML-encoded — script tags are rendered as plain text.";
        return View("XSS", vm);
    }

    // ── COMMAND INJECTION ─────────────────────────────────────────────────────

    public IActionResult CommandInjection() => View(new CommandViewModel());

    // VULNERABLE: User input injected directly into shell command — try: 127.0.0.1 & dir
    [HttpPost]
    public IActionResult CommandVulnerable(CommandViewModel vm)
    {
        vm.IsVulnerable = true;
        vm.Command = $"cmd.exe /c ping -n 1 {vm.Host}";
        try
        {
            var psi = new ProcessStartInfo("cmd.exe", $"/c ping -n 1 {vm.Host}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi)!;
            vm.Output = proc.StandardOutput.ReadToEnd();
            if (string.IsNullOrWhiteSpace(vm.Output)) vm.Output = proc.StandardError.ReadToEnd();
            proc.WaitForExit(5000);
        }
        catch (Exception ex) { vm.Output = $"Error: {ex.Message}"; }
        return View("CommandInjection", vm);
    }

    // SECURE: Validate input, avoid shell; only pass to dedicated process
    [HttpPost]
    public IActionResult CommandSecure(CommandViewModel vm)
    {
        vm.IsVulnerable = false;

        // Allow only valid hostnames/IPs
        if (!System.Text.RegularExpressions.Regex.IsMatch(vm.Host, @"^[a-zA-Z0-9.\-]{1,100}$"))
        {
            vm.Output = "Blocked: Invalid hostname — only alphanumeric, dots, and hyphens allowed.";
            vm.Command = "Command blocked due to input validation";
            return View("CommandInjection", vm);
        }

        vm.Command = $"ping -n 1 {vm.Host}  [validated input, no shell]";
        try
        {
            var psi = new ProcessStartInfo("ping", $"-n 1 {vm.Host}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi)!;
            vm.Output = proc.StandardOutput.ReadToEnd();
            if (string.IsNullOrWhiteSpace(vm.Output)) vm.Output = proc.StandardError.ReadToEnd();
            proc.WaitForExit(5000);
        }
        catch (Exception ex) { vm.Output = $"Error: {ex.Message}"; }
        return View("CommandInjection", vm);
    }
}
