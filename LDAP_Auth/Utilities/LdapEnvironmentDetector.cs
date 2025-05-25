using LDAP_Auth.Models;
using System.DirectoryServices.ActiveDirectory;

namespace LDAP_Auth.Utilities;

public class LdapEnvironmentDetector
{
    public static LdapSettings AutoDetect()
    {
        var domain = Domain.GetComputerDomain().Name;
        var baseDn = string.Join(",", domain.Split('.').Select(part => $"DC={part}"));
        var controller = Domain.GetComputerDomain().FindDomainController().Name;

        return new LdapSettings
        {
            Domain = domain,
            BaseDn = baseDn,
            LdapPath = $"LDAP://{controller}"
        };
    }
}