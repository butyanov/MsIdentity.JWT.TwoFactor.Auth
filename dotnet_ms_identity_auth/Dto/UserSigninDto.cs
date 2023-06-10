using System.ComponentModel.DataAnnotations;

namespace dotnet_ms_identity_auth.Dto;

public class UserSigninDto
{
    [Required]
    [RegularExpression("^[a-z]+$")]
    public string Username { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }
    
    [Required]
    [RegularExpression("^[0-9!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]*$")]
    [DataType(DataType.Password)]
    public string Password { get; set; }
}