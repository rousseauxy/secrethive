using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Infrastructure.Sqlite;

public static class SqliteProvider
{
    public static readonly string MigrationsAssembly = typeof(SqliteProvider).Assembly.GetName().Name!;

    public static DbContextOptionsBuilder UseSecretHiveSqlite(this DbContextOptionsBuilder builder, string connectionString) =>
        builder.UseSqlite(connectionString, sqlite => sqlite.MigrationsAssembly(MigrationsAssembly));
}

/// <summary>Used by <c>dotnet ef migrations add --project src/SecretHive.Infrastructure.Sqlite</c>.</summary>
public sealed class SqliteDesignTimeFactory : IDesignTimeDbContextFactory<SecretHiveDbContext>
{
    public SecretHiveDbContext CreateDbContext(string[] args)
    {
        var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
        builder.UseSecretHiveSqlite("Data Source=design-time.db");
        return new SecretHiveDbContext(builder.Options);
    }
}
