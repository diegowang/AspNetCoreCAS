
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace AspNetCoreCAS.Models
{
    public class ApplicationRole : IdentityRole
    {
        public string Description { get; set; }
    }
}
