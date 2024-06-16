using BlazorAuto8CookieApp.Client.Auth;
using BlazorAuto8CookieApp.Data;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Security.Claims;

namespace BlazorAuto8CookieApp.Auth
{
    public class CustomAuthStateProvider : RevalidatingServerAuthenticationStateProvider
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly PersistentComponentState _state;
        private readonly IdentityOptions _options;

        private readonly PersistingComponentStateSubscription subscription;

        private Task<AuthenticationState>? _authenticationStateTask;

        public CustomAuthStateProvider(
            ILoggerFactory loggerFactory,
            IServiceScopeFactory serviceScopeFactory,
            PersistentComponentState persistentComponentState,
            IOptions<IdentityOptions> optionsAccessor)
            : base(loggerFactory)
        {
            _scopeFactory = serviceScopeFactory;
            _state = persistentComponentState;
            _options = optionsAccessor.Value;

            AuthenticationStateChanged += OnAuthenticationStateChanged;
            subscription = _state.RegisterOnPersisting(OnPersistingAsync, RenderMode.InteractiveWebAssembly);
        }

        protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

        protected override async Task<bool> ValidateAuthenticationStateAsync(
            AuthenticationState authenticationState, CancellationToken cancellationToken)
        {
            // Get the user manager from a new scope to ensure it fetches fresh data
            await using var scope = _scopeFactory.CreateAsyncScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            return await ValidateSecurityStampAsync(userManager, authenticationState.User);
        }

        private async Task<bool> ValidateSecurityStampAsync(UserManager<ApplicationUser> userManager, ClaimsPrincipal principal)
        {
            var user = await userManager.GetUserAsync(principal);
            if (user is null)
            {
                return false;
            }
            else if (!userManager.SupportsUserSecurityStamp)
            {
                return true;
            }
            else
            {
                var principalStamp = principal.FindFirstValue(_options.ClaimsIdentity.SecurityStampClaimType);
                var userStamp = await userManager.GetSecurityStampAsync(user);
                return principalStamp == userStamp;
            }
        }

        private void OnAuthenticationStateChanged(Task<AuthenticationState> task)
        {
            _authenticationStateTask = task;
        }

        private async Task OnPersistingAsync()
        {
            try
            {
                if (_authenticationStateTask is null)
                {
                    throw new UnreachableException($"Authentication state not set in {nameof(OnPersistingAsync)}().");
                }

                var authenticationState = await _authenticationStateTask;
                var principal = authenticationState.User;

                if (principal.Identity?.IsAuthenticated == true)
                {
                    var userId = principal.FindFirst(_options.ClaimsIdentity.UserIdClaimType)?.Value;
                    var userName = principal.FindFirst(_options.ClaimsIdentity.UserNameClaimType)?.Value;
                    var email = principal.FindFirst(_options.ClaimsIdentity.EmailClaimType)?.Value;

                    var user = new User();
                    user.Id = userId;
                    user.UserName = userName;
                    user.Email = email;

                    await using var scope = _scopeFactory.CreateAsyncScope();
                    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                    var userInDb = await userManager.GetUserAsync(principal);
                    if (userInDb is not null)
                    {
                        user.FirstName = userInDb.FirstName;
                        user.LastName = userInDb.LastName;

                        var roles = await userManager.GetRolesAsync(userInDb);
                        if (roles != null && roles.Any())
                        {
                            user.Roles = roles.ToList();
                        }
                    }

                    _state.PersistAsJson(nameof(User), user);
                }
            }
            catch (Exception ex)
            {

            }
            
        }

        protected override void Dispose(bool disposing)
        {
            subscription.Dispose();
            AuthenticationStateChanged -= OnAuthenticationStateChanged;
            base.Dispose(disposing);
        }
    }
}
