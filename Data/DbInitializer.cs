using OWASPDemo.Models;

namespace OWASPDemo.Data;

public static class DbInitializer
{
    public static void Initialize(AppDbContext context)
    {
        context.Database.EnsureCreated();

        if (!context.Users.Any())
        {
            context.Users.AddRange(
                new User
                {
                    Username = "alice", Email = "alice@example.com",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("password123"),
                    PasswordPlain = "password123",
                    Role = "user", AccountBalance = 5000.00m,
                    CreditCard = "4111111111111111", SSN = "123-45-6789"
                },
                new User
                {
                    Username = "bob", Email = "bob@example.com",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("bobpass"),
                    PasswordPlain = "bobpass",
                    Role = "user", AccountBalance = 12500.00m,
                    CreditCard = "4222222222222222", SSN = "987-65-4321"
                },
                new User
                {
                    Username = "admin", Email = "admin@example.com",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("admin123"),
                    PasswordPlain = "admin123",
                    Role = "admin", AccountBalance = 99999.00m,
                    CreditCard = "4333333333333333", SSN = "000-00-0001"
                }
            );
        }

        if (!context.Products.Any())
        {
            context.Products.AddRange(
                new Product { Name = "Laptop Pro", Description = "High-performance laptop", Price = 1299.99m, Category = "Electronics" },
                new Product { Name = "Wireless Mouse", Description = "Ergonomic wireless mouse", Price = 29.99m, Category = "Accessories" },
                new Product { Name = "USB Hub", Description = "7-port USB 3.0 hub", Price = 49.99m, Category = "Accessories" },
                new Product { Name = "Monitor 4K", Description = "27-inch 4K display", Price = 499.99m, Category = "Electronics" },
                new Product { Name = "Keyboard Mech", Description = "Mechanical keyboard", Price = 149.99m, Category = "Accessories" }
            );
        }

        context.SaveChanges();
    }
}
