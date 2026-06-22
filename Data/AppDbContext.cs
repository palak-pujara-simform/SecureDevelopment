using Microsoft.EntityFrameworkCore;
using OWASPDemo.Models;

namespace OWASPDemo.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
    public DbSet<Product> Products { get; set; }
    public DbSet<AuditLog> AuditLogs { get; set; }
}
