using System.Security.Claims;
using AbacAuthorization.Utils;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AbacAuthorization.Endpoints;

public record RegisterRequest(string Email, string Password, string? Department, string? Role);
public record LoginRequest(string Email, string Password);
public record AuthResponse(string Token, DateTime ExpiresAt);

public static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/register",
            async ([FromBody] RegisterRequest request, UserManager<IdentityUser> userManager,
                RoleManager<IdentityRole> roleManager) =>
            {
                var user = new IdentityUser(request.Email) { Email = request.Email };

                var result = await userManager.CreateAsync(user, request.Password);
                if (!result.Succeeded)
                {
                    return Results.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
                }

                if (request.Role is not null)
                {
                    if (!await roleManager.RoleExistsAsync(request.Role))
                    {
                        await roleManager.CreateAsync(new IdentityRole(request.Role));
                    }
                    await userManager.AddToRoleAsync(user, request.Role);
                }

                if (request.Department is not null)
                {
                    await userManager.AddClaimAsync(user, new Claim("Department", request.Department));
                }                

                return Results.Created();
            }).AllowAnonymous();

        app.MapPost("/auth/login",
            async ([FromBody] LoginRequest request, UserManager<IdentityUser> userManager,
                SignInManager<IdentityUser> signInManager, IConfiguration configuration) =>
            {
                var user = await userManager.FindByEmailAsync(request.Email);
                if (user is null)
                {
                    return Results.Unauthorized();
                }

                var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
                if (!result.Succeeded)
                {
                    return Results.Unauthorized();
                }

                var claims = await userManager.GetClaimsAsync(user);
                var roles = await userManager.GetRolesAsync(user);
                var (token, expires) = JwtTokenGenerator.GenerateToken(user, claims, roles, configuration);

                return Results.Ok(new AuthResponse(Token: token, ExpiresAt: expires));
            }).AllowAnonymous();

        return app;
    }
}
