namespace OWASPDemo.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string PasswordPlain { get; set; } = string.Empty;
    public string Role { get; set; } = "user";
    public decimal AccountBalance { get; set; }
    public string? CreditCard { get; set; }
    public string? SSN { get; set; }
    public int LoginAttempts { get; set; }
    public DateTime? LockedUntil { get; set; }
    public string? PasswordResetToken { get; set; }
    public DateTime? ResetTokenExpiry { get; set; }
    public int ResetRequestCount { get; set; }
    public DateTime? LastResetRequest { get; set; }
}
