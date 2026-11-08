using JSONWebTokenAuthenticationServer.Data;
using JSONWebTokenAuthenticationServer.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("JSONWebTokenDbConnection");

builder.Services.AddDbContext<JSONWebTokenDatabaseContext>(options =>
    options.UseSqlServer(connectionString));

// Add services to the container.

builder.Services.AddControllers();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, CancellationToken) =>
    {
        document.Info.Version = "v1";
        document.Info.Title = "JSON Web Token Authentication API";
        document.Info.Description = "API for authenticating users with JSON Web Tokens";
        return Task.CompletedTask;
    });
});

// Register the KeyRotationService as a hosted (background) service
// This service handles periodic rotation of signing keys to enhance security
builder.Services.AddHostedService<KeyRotationService>();

builder.Services.AddAuthentication(options =>
{
    // This indicates the authentication scheme that will be used by default when the app attempts to authenticate a user.
    // Which authentication handler to use for verifying who the user is by default.
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;

    // This indicates the authentication scheme that will be used by default when the app encounters an authentication challenge. 
    // Which authentication handler to use for responding to failed authentication or authorization attempts.
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    // Define token validation parameters to ensure tokens are valid and trustworthy
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, // Ensure the token was issued by a trusted issuer]
        ValidIssuer = builder.Configuration["Jwt:Issuer"], // The expected issuer value from configuration
        ValidateAudience = false, // Disable audience validation (can be enabled as needed)
        ValidateLifetime = true, // Ensure the token has not expired
        ValidateIssuerSigningKey = true, // Ensure the token's signature is valid

        // Define a custom IssuerSigningKeyResolver to dynamically retrieve signing keys from the JWKS endpoint
        IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
        {
            // Initialize an HttpClient instance for fetching the JWKS
            var httpClient = new HttpClient();

            // Synchronously fetch the JWKS (JSON Web Key Set) from the specified URL
            var jwks = httpClient.GetStringAsync($"{builder.Configuration["Jwt:Issuer"]}/api/JWKS/jwks.json").Result;

            // Parse the fetched JWKS into a JsonWebKeySet object
            var keys = new JsonWebKeySet(jwks);

            // Return the collection of JsonWebKey objects for token validation
            return keys.Keys;
        }
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(opt =>
    {
        opt.WithTitle("JSON Web Token Authentication API");
        opt.WithTheme(ScalarTheme.DeepSpace);
    });
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
