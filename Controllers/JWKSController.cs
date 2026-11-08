using JSONWebTokenAuthenticationServer.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JSONWebTokenAuthenticationServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JWKSController : ControllerBase
    {
        private readonly JSONWebTokenDatabaseContext _context;

        public JWKSController(JSONWebTokenDatabaseContext context)
        {
            _context = context;
        }

        [HttpGet("jwks.json")]
        public IActionResult GetJWKS()
        {
            // Retrieve all active signing keys from the database
            var keys = _context.SigningKeys.Where(k => k.IsActive).ToList();

            // Construct the JWKS (JSON Web Key Set) object
            var jwks = new
            {
                //kty, use, kid, alg, n, e
                keys = keys.Select(k => new
                {
                    kty = "RSA",    // Key type (RSA)
                    use = "sig",    // Usage (sig for signature)
                    kid = k.KeyId,  // Key ID to identify the key
                    alg = "RS256",  // Algorithm (RS256 for RSA SHA-256)
                    n = Base64UrlEncoder.Encode(GetModulus(k.PublicKey)), // Modulus (Base64URL-encoded)
                    e = Base64UrlEncoder.Encode(GetExponent(k.PublicKey)) // Exponent (Base64URL-encoded)
                })
            };

            // Return the JWKS object as a JSON response with status code 200 OK
            return Ok(jwks);
        }

        // Helper method to extract the modulus component from a Base64-encoded public key
        private byte[] GetModulus(string publicKey)
        {

            // Create a new RSA instance for cryptographic operations
            using var rsa = RSA.Create();

            // Import the RSA public key from its Base64-encoded representation
            rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);

            // Export the RSA parameters without including the private key
            var parameters = rsa.ExportParameters(false);

            if(parameters.Modulus == null)
            {
                throw new InvalidOperationException("RSA parameters are not valid.");
            }

            // Return the modulus component of the RSA key
            return parameters.Modulus;

        }

        // Helper method to extract the exponent component from a Base64-encoded public key
        private byte[] GetExponent(string publicKey)
        {
            // Create a new RSA instance for cryptographic operations
            using var rsa = RSA.Create();

            // Import the RSA public key from its Base64-encoded representation
            rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);

            // Export the RSA parameters without including the private key
            var parameters = rsa.ExportParameters(false);

            if(parameters.Exponent == null)
            {
                throw new InvalidOperationException("RSA parameters are not valid.");
            }

            // Return the exponent component of the RSA key
            return parameters.Exponent;
        }
    }
}
