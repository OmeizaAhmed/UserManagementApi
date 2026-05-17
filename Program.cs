using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);


var jwtIssuer = "UserManagementApi";
var jwtAudience = "UserManagementApiClients";
var jwtSecret = "YourSuperSecretSigningKey-ChangeThisInProduction"; // Only for testing and learning purpose
var tokenIssuanceSecret = "issue-demo-token-secret";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Unhandled exception while processing request {Method} {Path}", context.Request.Method, context.Request.Path);

        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/json";

        await context.Response.WriteAsJsonAsync(new
        {
            Error = "An unexpected error occurred.",
            RequestId = context.TraceIdentifier
        });
    }
});

app.Use(async (context, next) =>
{
    await next();

    app.Logger.LogInformation("HTTP {Method} {Path} responded {StatusCode}",
        context.Request.Method,
        context.Request.Path,
        context.Response.StatusCode);
});

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/token", (TokenRequest request) =>
{
    if (request.ApiKey != tokenIssuanceSecret)
    {
        return Results.Unauthorized();
    }

    var keyBytes = Encoding.UTF8.GetBytes(jwtSecret);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "demo-user"),
            new Claim(ClaimTypes.Name, "demo-user")
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        Issuer = jwtIssuer,
        Audience = jwtAudience,
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256)
    };

    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.CreateToken(tokenDescriptor);
    var tokenString = tokenHandler.WriteToken(token);

    return Results.Ok(new
    {
        access_token = tokenString,
        token_type = "Bearer",
        expires_in = 3600
    });
});

app.MapGet("/users", () => Results.Ok(UserStore.Users)).RequireAuthorization();

app.MapGet("/users/{id:int}", (int id) =>
{
    var user = UserStore.Users.FirstOrDefault(u => u.Id == id);
    return user is not null ? Results.Ok(user) : Results.NotFound();
}).RequireAuthorization();

app.MapPost("/users", (UserCreateRequest request) =>
{
    if (!ValidateUserInput(request.Name, request.Email, out var errorMessage))
    {
        return Results.BadRequest(new { Error = errorMessage });
    }

    var user = new User
    {
        Id = UserStore.NextId++,
        Name = request.Name.Trim(),
        Email = request.Email.Trim()
    };

    UserStore.Users.Add(user);
    return Results.Created($"/users/{user.Id}", user);
}).RequireAuthorization();

app.MapPut("/users/{id:int}", (int id, UserUpdateRequest request) =>
{
    var user = UserStore.Users.FirstOrDefault(u => u.Id == id);
    if (user is null)
    {
        return Results.NotFound();
    }

    if (!ValidateUserInput(request.Name, request.Email, out var errorMessage))
    {
        return Results.BadRequest(new { Error = errorMessage });
    }

    user.Name = request.Name.Trim();
    user.Email = request.Email.Trim();
    return Results.NoContent();
}).RequireAuthorization();

app.MapDelete("/users/{id:int}", (int id) =>
{
    var user = UserStore.Users.FirstOrDefault(u => u.Id == id);
    if (user is null)
    {
        return Results.NotFound();
    }

    UserStore.Users.Remove(user);
    return Results.NoContent();
}).RequireAuthorization();

app.Run();

static bool ValidateUserInput(string? name, string? email, out string errorMessage)
{
    if (string.IsNullOrWhiteSpace(name))
    {
        errorMessage = "Name is required.";
        return false;
    }

    if (string.IsNullOrWhiteSpace(email))
    {
        errorMessage = "Email is required.";
        return false;
    }

    name = name.Trim();
    email = email.Trim();

    if (name.Length > 100)
    {
        errorMessage = "Name must be 100 characters or fewer.";
        return false;
    }

    if (email.Length > 256)
    {
        errorMessage = "Email must be 256 characters or fewer.";
        return false;
    }

    if (Regex.IsMatch(name, @"[<>""'/%]"))
    {
        errorMessage = "Name contains invalid characters.";
        return false;
    }

    if (Regex.IsMatch(email, @"[<>""'/%]"))
    {
        errorMessage = "Email contains invalid characters.";
        return false;
    }

    var emailPattern = @"^[^\s@]+@[^\s@]+\.[^\s@]+$";
    if (!Regex.IsMatch(email, emailPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase))
    {
        errorMessage = "Email is not in a valid format.";
        return false;
    }

    errorMessage = string.Empty;
    return true;
}

static class UserStore
{
    public static readonly List<User> Users = new()
    {
        new User { Id = 1, Name = "Alice", Email = "alice@example.com" },
        new User { Id = 2, Name = "Bob", Email = "bob@example.com" }
    };

    public static int NextId = Users.Max(u => u.Id) + 1;
}

internal class User
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

internal class UserCreateRequest
{
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

internal class UserUpdateRequest
{
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

internal class TokenRequest
{
    public string ApiKey { get; set; } = string.Empty;
}
