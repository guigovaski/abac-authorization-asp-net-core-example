using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AbacAuthorization.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.Options;

namespace AbacAuthorization.Auth.Handlers;

public static class DocumentOperations
{
    public static readonly OperationAuthorizationRequirement Create = new() { Name = nameof(Create) };
    public static readonly OperationAuthorizationRequirement Read = new() { Name = nameof(Read) };
    public static readonly OperationAuthorizationRequirement Update = new() { Name = nameof(Update) };
    public static readonly OperationAuthorizationRequirement Delete = new() { Name = nameof(Delete) };
    public static readonly OperationAuthorizationRequirement ReadPrivate = new() { Name = nameof(ReadPrivate) };
}

public class BusinessHoursOptions
{
    public string TimeZoneId { get; set; } = "UTC";
    public TimeSpan Start { get; set; } = new(7, 0, 0);
    public TimeSpan End { get; set; } = new(23, 0, 0);
}

public class DocumentAuthorizationHandler(TimeProvider timeProvider, IOptions<BusinessHoursOptions> businessHours) :
    AuthorizationHandler<OperationAuthorizationRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Document resource)
    {
        var isAuthorized = requirement.Name switch
        {
            // Criar: o usuário só pode criar documentos no próprio departamento            
            nameof(DocumentOperations.Create) =>
                IsSameDepartment(context, resource),

            // Ler: o usuário deve ser o autor OU pertencer ao mesmo departamento do documento
            nameof(DocumentOperations.Read) =>
                IsSameAuthor(context, resource) || IsSameDepartment(context, resource),

            // Atualizar: o usuário deve ser o autor e manter o documento em seu departamento
            nameof(DocumentOperations.Update) =>
                IsSameAuthor(context, resource) && IsSameDepartment(context, resource),

            // Deletar: apenas o próprio autor pode excluir o documento
            nameof(DocumentOperations.Delete) =>
                IsSameAuthor(context, resource),

            // Leitura privada/administrativa: requer role "admin" e horário comercial configurado
            nameof(DocumentOperations.ReadPrivate) =>
                context.User.IsInRole("admin") && IsWithinAllowedTime(),

            _ => false
        };

        if (isAuthorized)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }

    private static bool IsSameAuthor(
        AuthorizationHandlerContext context,
        Document resource)
    {
        var subjectId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                        ?? context.User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

        return !string.IsNullOrEmpty(subjectId) && subjectId == resource.Author;
    }

    private static bool IsSameDepartment(
        AuthorizationHandlerContext context,
        Document resource)
    {
        var userDepartment = context.User.FindFirst("Department")?.Value;

        return !string.IsNullOrEmpty(userDepartment) &&
               string.Equals(userDepartment, resource.Department, StringComparison.OrdinalIgnoreCase);
    }

    private bool IsWithinAllowedTime()
    {
        var options = businessHours.Value;
        var timeZone = TimeZoneInfo.FindSystemTimeZoneById(options.TimeZoneId);
        var now = TimeZoneInfo.ConvertTime(timeProvider.GetUtcNow(), timeZone).TimeOfDay;

        return now >= options.Start && now < options.End;
    }
}

