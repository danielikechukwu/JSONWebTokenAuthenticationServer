using JSONWebTokenAuthenticationServer.Data;
using JSONWebTokenAuthenticationServer.DTOs;
using JSONWebTokenAuthenticationServer.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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

            if(client == null)
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

        // Private method responsible for generating a JWT token for an authenticated user
        private string GenerateJwtToken(User user, Client client)
        {
            // Retrieve the active signing key from the SigningKeys table
            var signingKey = _context.SigningKeys.FirstOrDefault(k => k.IsActive);

            // If no active signing key is found, throw an exception
            if (signingKey == null)
            {
                throw new Exception("No active signing key found. Please ensure that a signing key is available.");
            }

            // Convert the Base64-encoded private key string back to a byte array
            var privateKeyBytes = Convert.FromBase64String(signingKey.PrivateKey);

            // Create a new RSA instance for cryptographic operations
            using var rsa = RSA.Create();

            // Import the RSA private key into the RSA instance
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

            // Create a new RsaSecurityKey using the RSA instance
            var rsaSecurityKey = new RsaSecurityKey(rsa)
            {
                // Assign the Key ID to link the JWT with the correct public key
                KeyId = signingKey.KeyId
            };

            // Define the signing credentials using the RSA security key and specifying the algorithm
            var creds = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);

            // Initialize a list of claims to include in the JWT
            var claims = new List<Claim>() {

                // Subject (sub) claim with the user's ID
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),

                // JWT ID (jti) claim with a unique identifier for the token
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),

                // Name claim with the user's first name
                new Claim(ClaimTypes.Name, user.FirstName),

                // NameIdentifier claim with the user's email
                new Claim(ClaimTypes.Email, user.Email)
            };

            foreach(var userRole in user.UserRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole.Role.Name));
            }

            // Define the JWT token's properties, including issuer, audience, claims, expiration, and signing credentials
            var tokenDescriptor = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"], // The token issuer, typically your application's URL
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
                );

            // Create a JWT token handler to serialize the token
            var tokenHandler = new JwtSecurityTokenHandler();

            // Serialize the token to a string
            var token = tokenHandler.WriteToken(tokenDescriptor);

            // Return the serialized JWT token
            return token;

        }
    }
}
