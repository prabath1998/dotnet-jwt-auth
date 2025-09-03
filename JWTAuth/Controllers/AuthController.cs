using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuth.Entities;
using JWTAuth.Models;
using JWTAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuth.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController(IAuthService authService) : Controller
{
    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserDto request)
    {
        var user = await authService.RegisterAsync(request);
        if (user is null)
        {
            return BadRequest("Username already exists");
        }

        return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<string>> Login(UserDto request)
    {
        var token = await authService.LoginAsync(request);
        if (token is null)
        {
            return BadRequest("Invalid username or password");
        }

        return Ok(token);
    }

    [Authorize]
    [HttpGet]
    public IActionResult AuthenticatedOnly()
    {
        return Ok("Authenticated");
    }
    
    [Authorize(Roles = "Admin")]
    [HttpGet("admin")]
    public IActionResult AdminOnly()
    {
        return Ok("Admin");
    }

}