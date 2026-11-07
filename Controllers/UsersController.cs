using JSONWebTokenAuthenticationServer.Data;
using JSONWebTokenAuthenticationServer.DTOs;
using JSONWebTokenAuthenticationServer.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JSONWebTokenAuthenticationServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly JSONWebTokenDatabaseContext _context;

        public UsersController(JSONWebTokenDatabaseContext context)
        {
            _context = context;
        }

        // Register a new user
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDto)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == registerDto.Email);

            if(existingUser != null)
            {
                return Conflict(new { message = "User with this email already exists." });
            }

            // Hash the password before storing it (you should implement a proper hashing mechanism), using Bcrypt for example
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(registerDto.Password);

            // Create a new user entity
            var newUser = new User
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.Lastname,
                Email = registerDto.Email,
                Password = hashedPassword
            };

            _context.Users.Add(newUser);

            await _context.SaveChangesAsync();

            var userRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User");

            if(userRole != null)
            {
                var userUserRole = new UserRole
                {
                    UserId = newUser.Id,
                    RoleId = userRole.Id
                };

                _context.UserRoles.Add(userUserRole);

                await _context.SaveChangesAsync();
            }

            return CreatedAtAction(nameof(GetProfile), new { id = newUser.Id }, new { message = "User registered successfully." });

        }

        // Retrieves the authenticated user's profile.
        [HttpGet("GetProfile")]
        [Authorize]
        public async Task <IActionResult> GetProfile()
        {
            // Extract the user's email from the JWT token claims.
            var emailClaim = User.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Email);

            if(emailClaim == null)
            {
                return Unauthorized(new { message = "Invalid token: Email claim not found." });
            }   

            var userEmail = emailClaim.Value;

            // Retrieve the user from the database, including roles.
            var user = await _context.Users
                .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => u.Email.ToLower() == userEmail.ToLower());

            if(user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            // Map the user entity to ProfileDTO.
            var profileDto = new ProfileDTO
            {
                Id = user.Id,
                Email = user.Email,
                Firstname = user.FirstName,
                Lastname = user.LastName,
                Roles = user.UserRoles.Select(ur => ur.Role.Name).ToList()
            };

            return Ok(profileDto);

        }

        // Updates the authenticated user's profile.
        [HttpPut("UpdateProfile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileDTO updateDto)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var emailClaim = User.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Email);

            if(emailClaim == null)
            {
                return Unauthorized(new { message = "Invalid token: Email claim not found." });
            }

            var userEmail = emailClaim.Value;

            // Retrieve the user from the database.
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == userEmail.ToLower());

            if(user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            if(!string.IsNullOrEmpty(updateDto.Firstname))
            {
                user.FirstName = updateDto.Firstname;
            }

            if(!string.IsNullOrEmpty(updateDto.Lastname))
            {
                user.LastName = updateDto.Lastname;
            }

            if(!string.IsNullOrEmpty(updateDto.Email))
            {
                // Check if the new email is already taken by another user.
                var emailTaken = await _context.Users.AnyAsync(u => u.Email.ToLower() == updateDto.Email.ToLower() && u.Id != user.Id);

                if(emailTaken)
                {
                    return Conflict(new { message = "Email is already taken by another user." });
                }

                user.Email = updateDto.Email;
            }

            if(!string.IsNullOrEmpty(updateDto.Password))
            {
                // Hash the new password before saving it.
                var hashedPassword = BCrypt.Net.BCrypt.HashPassword(updateDto.Password);

                user.Password = hashedPassword;
            }

            await _context.SaveChangesAsync();

            return Ok(new { message = "Profile updated successfully." });
        }


    }
}
