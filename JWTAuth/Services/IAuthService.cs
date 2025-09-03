using JWTAuth.Entities;
using JWTAuth.Models;

namespace JWTAuth.Services;

public interface IAuthService
{
    Task<User?> RegisterAsync(UserDto request);
    Task<string?> LoginAsync(UserDto request);
    
}