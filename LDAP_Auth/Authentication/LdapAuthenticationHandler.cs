using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using LDAP_Auth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LDAP_Auth.Authentication;

public class LdapAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ILdapAuthService _ldapService;

    public LdapAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        ILdapAuthService ldapService)
        : base(options, logger, encoder, clock)
    {
        _ldapService = ldapService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
            return AuthenticateResult.Fail("Missing Authorization Header");

        try
        {
            var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
            if (authHeader.Scheme != "Basic")
                return AuthenticateResult.Fail("Invalid Authorization Scheme");

            var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter ?? "")).Split(':', 2);
            if (credentials.Length != 2)
                return AuthenticateResult.Fail("Invalid Basic Authentication Header");

            var username = credentials[0];
            var password = credentials[1];

            var isAuthenticated = await _ldapService.AuthenticateAsync(username, password);
            if (!isAuthenticated)
                return AuthenticateResult.Fail("Invalid Username or Password");

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.NameIdentifier, username),
                new Claim(ClaimTypes.AuthenticationMethod, "LDAP")
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            return AuthenticateResult.Fail($"Authentication failed: {ex.Message}");
        }
    }
}
