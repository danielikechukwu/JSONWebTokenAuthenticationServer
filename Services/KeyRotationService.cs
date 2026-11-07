using JSONWebTokenAuthenticationServer.Data;
using JSONWebTokenAuthenticationServer.Entities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace JSONWebTokenAuthenticationServer.Services
{
    public class KeyRotationService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;

        private readonly TimeSpan _rotationInterval = TimeSpan.FromDays(7); // Rotate keys every 7 days

        public KeyRotationService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Loop that runs until the service is stopped
            while (!stoppingToken.IsCancellationRequested)
            {
                await RotateKeysAsync();

                await Task.Delay(_rotationInterval, stoppingToken);
            }
        }

        private async Task RotateKeysAsync()
        {
            using var scope = _serviceProvider.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<JSONWebTokenDatabaseContext>();

            var activeKey = await context.SigningKeys.FirstOrDefaultAsync(k => k.IsActive);

            if(activeKey == null || activeKey.ExpiresAt <= DateTime.UtcNow.AddDays(10))
            {
                if(activeKey != null)
                {
                    activeKey.IsActive = false;

                    context.SigningKeys.Update(activeKey);
                }

                using var rsa = RSA.Create(2048);

                var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

                var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());

                var newKeyId = Guid.NewGuid().ToString();

                var newKey = new SigningKey() {
                    KeyId = newKeyId,
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddYears(1) // Set expiration to 30 days from now
                };

                await context.SigningKeys.AddAsync(newKey);

                await context.SaveChangesAsync();
            }
        }
    }
}
