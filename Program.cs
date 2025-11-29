using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Add global exception handler
app.UseGlobalExceptionHandler();

// Add token validation middleware
app.UseTokenValidation();


// Add logging middleware
app.UseRequestResponseLogging();


app.Map("/", () => "User Management API");


var users = new Dictionary<int, User>();
var nextId = 1; // auto-increment counter

// Create (POST)
app.MapPost("/users", (User user) =>
{
    if (!ValidateUser(user, out var error))
        return Results.BadRequest(new { message = error });

    user.Id = nextId++;
    users[user.Id] = user;
    return Results.Created($"/users/{user.Id}", user);
});

// Read All (GET)
app.MapGet("/users", () => Results.Ok(users.Values));

// Read Single (GET by Id)
app.MapGet("/users/{id}", (int id) =>
{
    return users.TryGetValue(id, out var user)
        ? Results.Ok(user)
        : Results.NotFound();
});

// Update (PUT)
app.MapPut("/users/{id}", (int id, User updatedUser) =>
{
    if (!users.ContainsKey(id))
        return Results.NotFound();

    if (!ValidateUser(updatedUser, out var error))
        return Results.BadRequest(new { message = error });

    updatedUser.Id = id;
    users[id] = updatedUser;
    return Results.Ok(updatedUser);
});

// Delete (DELETE)
app.MapDelete("/users/{id}", (int id) =>
{
    return users.Remove(id)
        ? Results.NoContent()
        : Results.NotFound();
});


// Helper method for validation
bool ValidateUser(User user, out string errorMessage)
{
    if (string.IsNullOrWhiteSpace(user.Username))
    {
        errorMessage = "Username cannot be empty.";
        return false;
    }

    if (string.IsNullOrWhiteSpace(user.UserEmail) || 
        !Regex.IsMatch(user.UserEmail, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
    {
        errorMessage = "Invalid email format.";
        return false;
    }

    if (user.UserAge <= 0 || user.UserAge > 120)
    {
        errorMessage = "Age must be between 1 and 120.";
        return false;
    }

    errorMessage = string.Empty;
    return true;
}
app.Run();

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string UserEmail { get; set; } = string.Empty;
    public int UserAge { get; set; }
}


////
/// Logging Middleware
/// 
public class RequestResponseLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestResponseLoggingMiddleware> _logger;

    public RequestResponseLoggingMiddleware(RequestDelegate next, ILogger<RequestResponseLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Log Request
        context.Request.EnableBuffering(); // allows multiple reads
        var requestBody = string.Empty;
        if (context.Request.ContentLength > 0)
        {
            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
            requestBody = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0; // reset stream position
        }

        _logger.LogInformation("HTTP Request: {method} {url} | Body: {body}",
            context.Request.Method,
            context.Request.Path,
            requestBody);

        // Capture Response
        var originalBodyStream = context.Response.Body;
        using var responseBody = new MemoryStream();
        context.Response.Body = responseBody;

        await _next(context);

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        var responseText = await new StreamReader(context.Response.Body).ReadToEndAsync();
        context.Response.Body.Seek(0, SeekOrigin.Begin);

        _logger.LogInformation("HTTP Response: {statusCode} | Body: {body}",
            context.Response.StatusCode,
            responseText);

        await responseBody.CopyToAsync(originalBodyStream);
    }
}

// Extension method for easy registration
public static class RequestResponseLoggingMiddlewareExtensions
{
    public static IApplicationBuilder UseRequestResponseLogging(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RequestResponseLoggingMiddleware>();
    }
}

///
/// Error handling Middleware
/// 

public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context); // continue pipeline
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception occurred.");

            context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
            context.Response.ContentType = "application/json";

            var errorResponse = new { error = "Internal server error." };

            await context.Response.WriteAsync(JsonSerializer.Serialize(errorResponse));
        }
    }
}

// Extension method for easy registration
public static class ExceptionHandlingMiddlewareExtensions
{
    public static IApplicationBuilder UseGlobalExceptionHandler(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<ExceptionHandlingMiddleware>();
    }
}

///
/// Authentication Middleware
/// 
public class TokenValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TokenValidationMiddleware> _logger;

    public TokenValidationMiddleware(RequestDelegate next, ILogger<TokenValidationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            // Check for Authorization header
            if (!context.Request.Headers.TryGetValue("Authorization", out var authHeader))
            {
                await UnauthorizedResponse(context, "Missing Authorization header.");
                return;
            }

            var token = authHeader.ToString().Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(token))
            {
                await UnauthorizedResponse(context, "Token is missing or empty.");
                return;
            }

            // Validate token (basic example using JwtSecurityTokenHandler)
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
            {
                await UnauthorizedResponse(context, "Invalid token format.");
                return;
            }

            var jwtToken = handler.ReadJwtToken(token);

            // Example validation: check expiry
            if (jwtToken.ValidTo < DateTime.UtcNow)
            {
                await UnauthorizedResponse(context, "Token has expired.");
                return;
            }

            // You can add more validation here (issuer, audience, signature, etc.)

            // If valid, continue pipeline
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token validation failed.");
            await UnauthorizedResponse(context, "Unauthorized access.");
        }
    }

    private static async Task UnauthorizedResponse(HttpContext context, string message)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        var errorResponse = new { error = message };
        await context.Response.WriteAsync(JsonSerializer.Serialize(errorResponse));
    }
}

// Extension method for easy registration
public static class TokenValidationMiddlewareExtensions
{
    public static IApplicationBuilder UseTokenValidation(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<TokenValidationMiddleware>();
    }
}

