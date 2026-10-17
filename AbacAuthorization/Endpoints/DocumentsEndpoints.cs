using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AbacAuthorization.Auth.Handlers;
using AbacAuthorization.Data;
using AbacAuthorization.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AbacAuthorization.Endpoints;

public record CreateDocumentRequest(string Title, string Department, string Content);

public static class DocumentsEndpoints
{
    public static IEndpointRouteBuilder MapDocumentsEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/documents", async ([FromBody] CreateDocumentRequest request,
            ClaimsPrincipal user, IAuthorizationService authorizationService, ApplicationDbContext dbContext) =>
        {
            var document = new Document
            {
                Id = Guid.NewGuid(),
                Title = request.Title,
                Department = request.Department,
                Author = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                         ?? user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                         ?? string.Empty,
                Content = Encoding.UTF8.GetBytes(request.Content)
            };
            
            var authResult = await authorizationService.AuthorizeAsync(user, document, DocumentOperations.Create);
            if (!authResult.Succeeded)
            {
                return Results.Forbid();
            }

            dbContext.Documents.Add(document);
            await dbContext.SaveChangesAsync();
            return Results.Created($"/documents/{document.Id}", document.Id);
        });

        app.MapGet("/documents/{id:guid}", async (Guid id,
            ClaimsPrincipal user, IAuthorizationService authorizationService, ApplicationDbContext dbContext) =>
        {
            var document = await dbContext.Documents.FindAsync(id);
            if (document is null)
            {
                return Results.NotFound();
            }

            var authResult = await authorizationService.AuthorizeAsync(user, document, DocumentOperations.Read);
            if (!authResult.Succeeded)
            {
                return Results.Forbid();
            }

            return Results.Ok(document);
        });
        
        app.MapGet("/admin/documents/{id:guid}", async (Guid id,
            ClaimsPrincipal user, IAuthorizationService authorizationService, ApplicationDbContext dbContext) =>
        {
            var document = await dbContext.Documents.FindAsync(id);
            if (document is null)
            {
                return Results.NotFound();
            }
            
            var authResult = await authorizationService.AuthorizeAsync(user, document, DocumentOperations.ReadPrivate);
            if (!authResult.Succeeded)
            {
                return Results.Forbid();
            }

            return Results.Ok(document);
        });

        app.MapDelete("/documents/{id:guid}", async (Guid id,
            ClaimsPrincipal user, IAuthorizationService authorizationService, ApplicationDbContext dbContext) =>
        {
            var document = await dbContext.Documents.FindAsync(id);
            if (document is null)
            {
                return Results.NotFound();
            }

            var authResult = await authorizationService.AuthorizeAsync(user, document, DocumentOperations.Delete);
            if (!authResult.Succeeded)
            {
                return Results.Forbid();
            }

            dbContext.Documents.Remove(document);
            await dbContext.SaveChangesAsync();
            return Results.NoContent();
        });

        app.MapPut("/documents/{id:guid}", async (Guid id, [FromBody] CreateDocumentRequest request,
            ClaimsPrincipal user, IAuthorizationService authorizationService, ApplicationDbContext dbContext) =>
        {
            var document = await dbContext.Documents.FindAsync(id);
            if (document is null)
            {
                return Results.NotFound();
            }

            // Autoriza o estado atual do documento (quem pode editá-lo hoje)
            var authResult = await authorizationService.AuthorizeAsync(user, document, DocumentOperations.Update);
            if (!authResult.Succeeded)
            {
                return Results.Forbid();
            }

            // Autoriza o estado proposto (o documento continua no departamento do usuário?)
            var proposed = new Document
            {
                Id = document.Id,
                Author = document.Author,
                Title = request.Title,
                Department = request.Department,
                Content = Encoding.UTF8.GetBytes(request.Content)
            };

            authResult = await authorizationService.AuthorizeAsync(user, proposed, DocumentOperations.Update);
            if (!authResult.Succeeded)
            {
                return Results.Forbid();
            }

            document.Title = proposed.Title;
            document.Department = proposed.Department;
            document.Content = proposed.Content;

            await dbContext.SaveChangesAsync();
            return Results.Ok(document);
        });

        return app;
    }
}