using System.ComponentModel.DataAnnotations;

namespace JSONWebTokenAuthenticationServer.Entities
{
    public class Client
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string ClientId { get; set; }

        // Name of the client application.
        [Required]
        [MaxLength(100)]
        public string Name { get; set; }

        // URL for the client application.
        [Required]
        [MaxLength(200)]
        public string ClientURL { get; set; }
    }
}
