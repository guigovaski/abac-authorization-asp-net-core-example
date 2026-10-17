namespace AbacAuthorization.Entities;

public class Document
{
    public Guid Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;
    public byte[] Content { get; set; } = [];
}
