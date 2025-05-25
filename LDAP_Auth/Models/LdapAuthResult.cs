using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LDAP_Auth.Models;

public class LdapAuthResult
{
    public bool IsAuthenticated { get; set; }
    public string Username { get; set; } = string.Empty;
    public List<string> Groups { get; set; } = new();
}
