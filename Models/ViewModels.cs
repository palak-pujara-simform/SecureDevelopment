namespace OWASPDemo.Models;

public class LoginViewModel
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool IsVulnerable { get; set; }
    public string? Message { get; set; }
    public bool Success { get; set; }
    public User? LoggedInUser { get; set; }
}

public class SqlSearchViewModel
{
    public string SearchTerm { get; set; } = string.Empty;
    public string? SqlQuery { get; set; }
    public List<Product>? Results { get; set; }
    public string? Error { get; set; }
    public bool IsVulnerable { get; set; }
}

public class XssViewModel
{
    public string Comment { get; set; } = string.Empty;
    public string? StoredComment { get; set; }
    public bool IsVulnerable { get; set; }
    public string? Message { get; set; }
}

public class CommandViewModel
{
    public string Host { get; set; } = string.Empty;
    public string? Output { get; set; }
    public bool IsVulnerable { get; set; }
    public string? Command { get; set; }
}

public class SSRFViewModel
{
    public string Url { get; set; } = string.Empty;
    public string? Response { get; set; }
    public bool IsVulnerable { get; set; }
    public string? Error { get; set; }
    public int StatusCode { get; set; }
}

public class CryptoViewModel
{
    public string Password { get; set; } = string.Empty;
    public string? Algorithm { get; set; }
    public string? Hash { get; set; }
    public bool IsVulnerable { get; set; }
    public string? Message { get; set; }
}

public class AccessControlViewModel
{
    public int UserId { get; set; }
    public User? RequestedUser { get; set; }
    public string? Error { get; set; }
    public bool IsVulnerable { get; set; }
    public int CurrentUserId { get; set; } = 1;
    public string CurrentUsername { get; set; } = "alice";
}

public class LoggingViewModel
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool IsVulnerable { get; set; }
    public string? LogOutput { get; set; }
    public string? Message { get; set; }
    public List<AuditLog>? RecentLogs { get; set; }
    public bool Success { get; set; }
}

public class PasswordResetViewModel
{
    public string Email { get; set; } = string.Empty;
    public bool IsVulnerable { get; set; }
    public string? Message { get; set; }
    public bool Success { get; set; }
}

public class ComponentsViewModel
{
    public string PackageName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public List<VulnerablePackage> VulnerablePackages { get; set; } = new();
}

public class VulnerablePackage
{
    public string Name { get; set; } = string.Empty;
    public string InstalledVersion { get; set; } = string.Empty;
    public string SafeVersion { get; set; } = string.Empty;
    public string CVE { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

public class DeserializeViewModel
{
    public string JsonInput { get; set; } = string.Empty;
    public string? Output { get; set; }
    public bool IsVulnerable { get; set; }
    public string? Error { get; set; }
}
