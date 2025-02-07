using AuthService.Models.Dtos;

namespace AuthService.Services.Interfaces;

public interface IAuthService
{
    Task<bool> RegisterUser(RegisterDto registerDto);
    Task<string> Login(LoginDto loginDto);
    Task<string> RefreshToken(string refreshToken);
}