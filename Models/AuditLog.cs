namespace OWASPDemo.Models;

public class AuditLog
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Action { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
}
