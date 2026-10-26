using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Infrastructure.SqlServer;

public static class SqlServerProvider
{
    public static readonly string MigrationsAssembly = typeof(SqlServerProvider).Assembly.GetName().Name!;

    public static DbContextOptionsBuilder UseSecretHiveSqlServer(this DbContextOptionsBuilder builder, string connectionString) =>
        builder.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(MigrationsAssembly));
}

/// <summary>Used by <c>dotnet ef migrations add --project src/SecretHive.Infrastructure.SqlServer</c>. Never connects.</summary>
public sealed class SqlServerDesignTimeFactory : IDesignTimeDbContextFactory<SecretHiveDbContext>
{
    public SecretHiveDbContext CreateDbContext(string[] args)
    {
        var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
        builder.UseSecretHiveSqlServer("Server=design-time;Database=design-time");
        return new SecretHiveDbContext(builder.Options);
    }
}
