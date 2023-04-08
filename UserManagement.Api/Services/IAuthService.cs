using UserManagement.Data.Models;

namespace UserManagement.Api.Services
{
    public interface IAuthService
    {
        Task<(int, string)> Registeration(RegistrationModel model, string role);
        Task<TokenViewModel> Login(LoginModel model);
        Task<TokenViewModel> GetRefreshToken(GetRefreshTokenViewModel model);
    }
}
