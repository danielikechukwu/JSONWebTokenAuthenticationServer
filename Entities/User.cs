using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace JSONWebTokenAuthenticationServer.Entities
{
    [Index(nameof(Email), Name = "IX_Unique_Email", IsUnique = true)]
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "First name is required")]
        public string FirstName { get; set; }

        public string? LastName { get; set; }
        
        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be between 6 and 100 characters")]
        public string Password { get; set; }

        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>(); // Navigation property for many-to-many relationship with Role

    }
}
