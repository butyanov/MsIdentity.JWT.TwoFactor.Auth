using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using dotnet_ms_identity_auth.Dto;
using dotnet_ms_identity_auth.Models;
using dotnet_ms_identity_auth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace dotnet_ms_identity_auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly SmtpSenderService _emailSender;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
        SmtpSenderService emailSender, IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _emailSender = emailSender;
        _configuration = configuration;
    }

    [HttpPost("Register")]
    public async Task<IActionResult> Register(UserSigninDto model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var user = new ApplicationUser { UserName = model.Username, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded) return BadRequest(result.Errors);

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var confirmationLink = Url.Action(nameof(ConfirmEmail), "Account", new { token, email = user.Email },
            Request.Scheme);
        await _emailSender.SendAsync(user.Email, $"Please confirm your email by clicking here: <a href='{confirmationLink}'>link</a>","Confirm your email");
        return Ok();
    }

    [HttpGet("ConfirmEmail")]
    public async Task<IActionResult> ConfirmEmail(string token, string email)
    {
        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email)) return BadRequest("Token or email is invalid");

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return BadRequest("User not found");

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok("Thank you for confirming your email");
    }

    [HttpPost("Login")]
    public async Task<IActionResult> Login(UserLoginDto model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null) return BadRequest("Invalid login attempt");

        var result =
            await _signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false,
                lockoutOnFailure: false);
        if (!result.Succeeded) return BadRequest("Invalid login attempt");

        if (!await _userManager.IsEmailConfirmedAsync(user)) return BadRequest("Email not confirmed");

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        };
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(claims : claims,
            expires: DateTime.Now.AddMinutes(30), signingCredentials: creds);

        return Ok(new
        {
            token = new JwtSecurityTokenHandler().WriteToken(token)
        });
    }

    [HttpGet("Secret")]
    [Authorize]
    public IActionResult Secret()
    {
        return Ok("This is your secret key");
    }
}