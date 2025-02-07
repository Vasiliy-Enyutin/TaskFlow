using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthService.Data;
using AuthService.Models.Dtos;
using AuthService.Models.Entities;
using AuthService.Services.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;

namespace AuthService.Services.Implementations;

public class AuthService : IAuthService
{
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly IDatabase _redis;

    public AuthService(AppDbContext context, IConfiguration configuration, IConnectionMultiplexer redis)
    {
        _context = context;
        _configuration = configuration;
        _redis = redis.GetDatabase();
    }

    public async Task<bool> RegisterUser(RegisterDto registerDto)
    {
        if (await _context.Users.AnyAsync(u => u.Email == registerDto.Email))
        {
            return false;
        }
        
        CreatePasswordHash(registerDto.Password, out var hash, out var salt);

        var user = new User
        {
            Email = registerDto.Email,
            PasswordHash = hash,
            PasswordSalt = salt
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<string> Login(LoginDto loginDto)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == loginDto.Email);
        if (user == null || !VerifyPassword(loginDto.Password, user.PasswordHash, user.PasswordSalt))
        {
            return string.Empty;
        }
        
        return GenerateJwtToken(user);
    }

    private void CreatePasswordHash(string password, out byte[] hash, out byte[] salt)
    {
        using var hmac = new HMACSHA512();
        salt = hmac.Key;
        hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
    }

    private bool VerifyPassword(string password, byte[] storedHash, byte[] storedSalt)
    {
        using var hmac = new HMACSHA512(storedSalt);
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        return computedHash.SequenceEqual(storedHash);
    }

    private string GenerateJwtToken(User user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.NameIdentifier, user.Id.ToString())
        };

        // Декодируем Base64 строку в байты
        var keyBytes = Convert.FromBase64String(_configuration["JwtSettings:SecretKey"]);
        var key = new SymmetricSecurityKey(keyBytes);
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            issuer: _configuration["JwtSettings:ValidIssuer"],
            audience: _configuration["JwtSettings:ValidAudience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(
                int.Parse(_configuration["JwtSettings:ExpiryInMinutes"])),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<string> RefreshToken(string refreshToken)
    {
        var userId = await _redis.StringGetAsync(refreshToken);
        if (userId.IsNullOrEmpty) return null;

        var user = await _context.Users.FindAsync(int.Parse(userId));
        if (user == null) return null;

        // Генерируем новый Access Token
        var newToken = GenerateJwtToken(user);
    
        // Обновляем Refresh Token в Redis
        await _redis.KeyDeleteAsync(refreshToken);
        var newRefreshToken = GenerateRefreshToken();
        await _redis.StringSetAsync(newRefreshToken, user.Id.ToString(), TimeSpan.FromDays(30));
    
        return newToken;
    }
    
    private string GenerateRefreshToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }
}