using System.ComponentModel.DataAnnotations;
using AuthService.Models.Dtos;
using AuthService.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([Required] RegisterDto registerDto)
    {
        var result = await _authService.RegisterUser(registerDto);
        return result ? Ok() : BadRequest("User already exists");
    }
    
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([Required][FromBody] RefreshTokenDto refreshTokenDto)
    {
        var token = await _authService.RefreshToken(refreshTokenDto.RefreshToken);
        return string.IsNullOrEmpty(token) ? Unauthorized() : Ok(new { Token = token });
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([Required] LoginDto loginDto)
    {
        var token = await _authService.Login(loginDto);
        return string.IsNullOrEmpty(token) ? Unauthorized() : Ok(new { Token = token });
    }
}