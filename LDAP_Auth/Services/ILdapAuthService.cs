using LDAP_Auth.Models;

namespace LDAP_Auth.Services;

public interface ILdapAuthService
{
    Task<LdapAuthResult> AuthenticateAsync(string username, string password);
}