
using System.Threading.Tasks;

namespace AspNetCoreCAS.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
    }
}
