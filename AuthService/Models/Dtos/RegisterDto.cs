using System.ComponentModel.DataAnnotations;

namespace AuthService.Models.Dtos;

public class RegisterDto
{
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;
    [Required, MinLength(6)]
    public string Password { get; set; } = string.Empty;
}