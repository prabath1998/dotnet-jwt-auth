using JWTAuth.Entities;
using Microsoft.EntityFrameworkCore;
namespace JWTAuth.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User>  Users { get; set; }
}