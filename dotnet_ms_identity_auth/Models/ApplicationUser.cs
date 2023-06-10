using Microsoft.AspNetCore.Identity;

namespace dotnet_ms_identity_auth.Models;

public class ApplicationUser : IdentityUser<Guid>
{
    public ApplicationUser()
    {
        Id = Guid.NewGuid();
    }
}