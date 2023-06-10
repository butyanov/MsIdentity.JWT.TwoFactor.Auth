using dotnet_ms_identity_auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace dotnet_ms_identity_auth.Data;

public class AppDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>
{
    public AppDbContext(
        DbContextOptions<AppDbContext> options
    ) : base(options)
    {
        
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<ApplicationUser>().Property(x => x.Id)
            .HasDefaultValueSql("gen_random_uuid()");
        builder.Entity<ApplicationUser>().HasIndex(x => x.Email).IsUnique();

    }
}