namespace LDAP_Auth.Services;

public interface ILdapAuthService
{
    Task<bool> AuthenticateAsync(string username, string password);
}