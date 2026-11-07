using JSONWebTokenAuthenticationServer.Data;
using JSONWebTokenAuthenticationServer.DTOs;
using JSONWebTokenAuthenticationServer.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JSONWebTokenAuthenticationServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        private readonly JSONWebTokenDatabaseContext _context;

        public AuthController(IConfiguration configuration, JSONWebTokenDatabaseContext context)
        {
            _configuration = configuration;
            _context = context;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDTO)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var client = await _context.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == loginDTO.ClientId);

            if(clients == null)
            {
                return Unauthorized(new { message = "Invalid client credentials" });
            }

            var user = await _context.Users
                .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => u.Email.ToLower() == loginDTO.Email.ToLower());

            if(user == null)
            {
                return Unauthorized(new { message = "Invalid user credentials" });
            }

            if (!BCrypt.Net.BCrypt.Verify(loginDTO.Password, user.Password))
            {
                return Unauthorized(new { message = "Invalid user credentials" });
            }

            // At this point, authentication is successful. Proceed to generate a JWT token.
            var token = GenerateJwtToken(user, client);

            return Ok(new { Token =  token });

        }

        private string GenerateJwtToken(User user, Client client)
        {
            var signingKey = _context.SigningKeys.FirstOrDefault(k => k.IsActive);

            if(signingKey == null)
            {
                throw new Exception("No active signing key found. Please ensure that a signing key is available.");
            }

            var privateKeyBytes = Convert.FromBase64String(signingKey.PrivateKey);

            using var rsa = RSA.Create();
        }   
    }
}
