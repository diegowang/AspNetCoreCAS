using System.Threading.Tasks;

namespace AspNetCoreCAS.Services
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}
