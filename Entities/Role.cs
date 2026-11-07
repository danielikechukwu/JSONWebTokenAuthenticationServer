using System.ComponentModel.DataAnnotations;

namespace JSONWebTokenAuthenticationServer.Entities
{
    public class Role
    {
        [Key]
        public int Id { get; set; }

        [Required(ErrorMessage = "Client name is required")]
        [MaxLength(50, ErrorMessage = "Client name cannot exceed 100 characters")]
        public string Name { get; set; }

        public string? Description { get; set; }

        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    }
}
