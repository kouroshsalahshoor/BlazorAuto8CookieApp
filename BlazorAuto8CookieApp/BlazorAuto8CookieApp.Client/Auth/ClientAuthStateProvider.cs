using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components;
using System.Security.Claims;

namespace BlazorAuto8CookieApp.Client.Auth
{
    internal class ClientAuthStateProvider : AuthenticationStateProvider
    {
        private static readonly Task<AuthenticationState> defaultUnauthenticatedTask =
            Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

        private readonly Task<AuthenticationState> authenticationStateTask = defaultUnauthenticatedTask;

        public ClientAuthStateProvider(PersistentComponentState state)
        {
            if (!state.TryTakeFromJson<User>(nameof(User), out var userInfo) || userInfo is null)
            {
                return;
            }

            List<Claim> claims = [
                new Claim(ClaimTypes.NameIdentifier, userInfo.Id!),
                new Claim(ClaimTypes.Name, userInfo.UserName!),
                new Claim(ClaimTypes.Email, userInfo.Email!),
                new Claim("firstname", userInfo.FirstName!),
                new Claim("lastname", userInfo.LastName!)
                ];

            //Claim[] claims = [
            //    new Claim(ClaimTypes.NameIdentifier, userInfo.Id!),
            //    new Claim(ClaimTypes.Name, userInfo.UserName!),
            //    new Claim(ClaimTypes.Email, userInfo.Email!),
            //    new Claim("firstname", userInfo.FirstName!),
            //    new Claim("lastname", userInfo.LastName!) 
            //    ];

            foreach (var role in userInfo.Roles!)
            {
                claims.Add(new Claim("role", role));
            }

            authenticationStateTask = Task.FromResult(
                new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims,
                    authenticationType: nameof(ClientAuthStateProvider)))));
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync() => authenticationStateTask;
    }
}
