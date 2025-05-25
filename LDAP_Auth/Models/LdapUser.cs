namespace LDAP_Auth.Models;

public class LdapUser
{
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string DistinguishedName { get; set; } = string.Empty;
}