using Microsoft.AspNetCore.Identity;

namespace BlazorAuto8CookieApp.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
    }
}
