namespace LDAP_Auth.Models;

public class LdapSettings
{
    public string LdapPath { get; set; } = string.Empty;
    public string BaseDn { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
}