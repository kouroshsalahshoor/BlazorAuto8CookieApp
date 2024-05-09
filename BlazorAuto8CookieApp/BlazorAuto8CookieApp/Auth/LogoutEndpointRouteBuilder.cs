using BlazorAuto8CookieApp.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace BlazorAuto8CookieApp.Auth
{
    internal static class LogoutEndpointRouteBuilder
    {
        public static IEndpointConventionBuilder MapLogoutEndpoint(this IEndpointRouteBuilder endpoints)
        {
            var accountGroup = endpoints.MapGroup("/Account");

            accountGroup.MapPost("/Logout", async (
                ClaimsPrincipal user,
                SignInManager<ApplicationUser> signInManager,
                [FromForm] string returnUrl) =>
            {
                await signInManager.SignOutAsync();
                return TypedResults.LocalRedirect($"~/{returnUrl}");
            });


            return accountGroup;
        }
    }
}
