using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using SecretHive.Domain.Entities;

namespace SecretHive.Infrastructure.Persistence;

/// <summary>
/// Provider-neutral model. Migrations live in SecretHive.Infrastructure.SqlServer and SecretHive.Infrastructure.Sqlite.
/// Rules that keep both providers identical: lookups use lower-cased columns (no collation dependence), dates are
/// UTC <see cref="DateTime"/> (SQLite cannot order DateTimeOffset), enums are stored as strings, and uniqueness is
/// never expressed with a filtered index.
/// </summary>
public sealed class SecretHiveDbContext(DbContextOptions<SecretHiveDbContext> options) : DbContext(options)
{
    private const int NameLength = 127;

    public DbSet<Vault> Vaults => Set<Vault>();

    public DbSet<Folder> Folders => Set<Folder>();

    public DbSet<FolderAssignment> FolderAssignments => Set<FolderAssignment>();

    public DbSet<Pin> Pins => Set<Pin>();

    public DbSet<SecretEntry> Entries => Set<SecretEntry>();

    public DbSet<EntryField> EntryFields => Set<EntryField>();

    public DbSet<StoredValue> Values => Set<StoredValue>();

    public DbSet<StoredVersion> Versions => Set<StoredVersion>();

    public DbSet<VersionItem> VersionItems => Set<VersionItem>();

    public DbSet<CertificateRecord> Certificates => Set<CertificateRecord>();

    public DbSet<AuditEvent> Audit => Set<AuditEvent>();

    public DbSet<User> Users => Set<User>();

    public DbSet<Group> Groups => Set<Group>();

    public DbSet<GroupMember> GroupMembers => Set<GroupMember>();

    public DbSet<VaultAssignment> VaultAssignments => Set<VaultAssignment>();

    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();

    public DbSet<NetworkGroup> NetworkGroups => Set<NetworkGroup>();

    public DbSet<AllowedNetwork> AllowedNetworks => Set<AllowedNetwork>();

    public DbSet<OidcProvider> OidcProviders => Set<OidcProvider>();

    public DbSet<ExternalLogin> ExternalLogins => Set<ExternalLogin>();

    public DbSet<GroupProviderLink> GroupProviderLinks => Set<GroupProviderLink>();

    public DbSet<AppSetting> Settings => Set<AppSetting>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        // Stored without a kind, so say what it is when it comes back.
        configurationBuilder.Properties<DateTime>().HaveConversion<UtcConverter>();
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Vault>(e =>
        {
            e.ToTable("Vaults");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.Name).HasMaxLength(NameLength);
            e.Property(x => x.NameKey).HasMaxLength(NameLength);
            e.HasIndex(x => x.NameKey).IsUnique();
            e.HasIndex(x => x.FolderId);
            e.HasOne<Folder>().WithMany().HasForeignKey(x => x.FolderId).OnDelete(DeleteBehavior.Restrict);
        });

        // A folder's parent is no foreign key: a backup restores the rows of a table in any order, and the service
        // keeps the tree whole (no circle, and a folder is deleted only when nothing is in it).
        modelBuilder.Entity<Folder>(e =>
        {
            e.ToTable("Folders");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.Name).HasMaxLength(NameLength);
            e.Property(x => x.NameKey).HasMaxLength(NameLength);
            e.HasIndex(x => x.NameKey).IsUnique();
            e.HasIndex(x => x.ParentId);
        });

        modelBuilder.Entity<Pin>(e =>
        {
            e.ToTable("Pins");
            e.HasKey(x => x.Key);
            e.HasIndex(x => new { x.UserKey, x.VaultId, x.EntryId });
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserKey).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Vault>().WithMany().HasForeignKey(x => x.VaultId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<FolderAssignment>(e =>
        {
            e.ToTable("FolderAssignments");
            e.HasKey(x => x.Key);
            e.Property(x => x.Role).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.GrantedBy).HasMaxLength(256);
            e.HasIndex(x => x.FolderId);
            e.HasIndex(x => x.UserKey);
            e.HasIndex(x => x.GroupKey);
            e.HasOne<Folder>().WithMany().HasForeignKey(x => x.FolderId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserKey).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Group>().WithMany().HasForeignKey(x => x.GroupKey).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SecretEntry>(e =>
        {
            e.ToTable("Entries");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.Name).HasMaxLength(NameLength);
            e.Property(x => x.NameKey).HasMaxLength(NameLength);
            e.Property(x => x.BinKey).HasMaxLength(32);
            e.Property(x => x.DeletedBy).HasMaxLength(256);
            e.Property(x => x.CopiedFrom).HasMaxLength(300);
            e.Ignore(x => x.InBin);
            e.HasIndex(x => new { x.VaultId, x.NameKey, x.BinKey }).IsUnique();
            e.HasIndex(x => x.ValueId);
            e.HasOne<Vault>().WithMany().HasForeignKey(x => x.VaultId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne<StoredValue>().WithMany().HasForeignKey(x => x.ValueId).OnDelete(DeleteBehavior.Restrict);
            e.HasMany(x => x.Fields).WithOne().HasForeignKey(x => x.EntryId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<EntryField>(e =>
        {
            e.ToTable("EntryFields");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.Name).HasMaxLength(63);
            e.Property(x => x.Type).HasConversion<string>().HasMaxLength(16);
            e.HasIndex(x => new { x.EntryId, x.Name }).IsUnique();
        });

        modelBuilder.Entity<StoredValue>(e =>
        {
            e.ToTable("Values");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.Kind).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.ContentType).HasMaxLength(127);
        });

        modelBuilder.Entity<StoredVersion>(e =>
        {
            e.ToTable("Versions");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.CreatedBy).HasMaxLength(256);
            e.Property(x => x.DataKeyId).HasMaxLength(16);
            e.HasIndex(x => new { x.ValueId, x.Number }).IsUnique();
            e.HasOne<StoredValue>().WithMany().HasForeignKey(x => x.ValueId).OnDelete(DeleteBehavior.Restrict);
            e.HasMany(x => x.Items).WithOne().HasForeignKey(x => x.VersionId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<VersionItem>(e =>
        {
            e.ToTable("VersionItems");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.Slot).HasMaxLength(80);
            e.Property(x => x.FieldType).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.FileName).HasMaxLength(255);
            e.HasIndex(x => new { x.VersionId, x.Slot }).IsUnique();
        });

        ConfigureSettings(modelBuilder);

        modelBuilder.Entity<User>(e =>
        {
            e.ToTable("Users");
            e.HasKey(x => x.Key);
            e.Property(x => x.UserName).HasMaxLength(64);
            e.Property(x => x.UserNameLower).HasMaxLength(64);
            e.HasIndex(x => x.UserNameLower).IsUnique();
            e.Property(x => x.DisplayName).HasMaxLength(128);
            e.Property(x => x.Email).HasMaxLength(256);
            e.Property(x => x.PasswordHash).HasMaxLength(256);
            e.Property(x => x.Role).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.SecurityStamp).HasMaxLength(64);
        });

        modelBuilder.Entity<Group>(e =>
        {
            e.ToTable("Groups");
            e.HasKey(x => x.Key);
            e.Property(x => x.Name).HasMaxLength(NameLength);
            e.Property(x => x.NameLower).HasMaxLength(NameLength);
            e.HasIndex(x => x.NameLower).IsUnique();
            e.Property(x => x.Description).HasMaxLength(512);
        });

        modelBuilder.Entity<GroupMember>(e =>
        {
            e.ToTable("GroupMembers");
            e.HasKey(x => x.Key);
            e.Property(x => x.Source).HasMaxLength(64);
            e.HasIndex(x => new { x.GroupKey, x.UserKey }).IsUnique();
            e.HasIndex(x => x.UserKey);
            e.HasOne<Group>().WithMany().HasForeignKey(x => x.GroupKey).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserKey).OnDelete(DeleteBehavior.Cascade);

            // Removed by the provider store when a provider goes: SQL Server refuses a second cascade path into this table.
            e.HasIndex(x => x.ProviderKey);
            e.HasOne<OidcProvider>().WithMany().HasForeignKey(x => x.ProviderKey).OnDelete(DeleteBehavior.NoAction);
        });

        modelBuilder.Entity<NetworkGroup>(e =>
        {
            e.ToTable("NetworkGroups");
            e.HasKey(x => x.Key);
            e.Property(x => x.Name).HasMaxLength(64);
            e.Property(x => x.NameLower).HasMaxLength(64);
            e.HasIndex(x => x.NameLower).IsUnique();
            e.Property(x => x.Description).HasMaxLength(256);
            e.Property(x => x.Ranges).HasMaxLength(4000);
        });

        modelBuilder.Entity<AllowedNetwork>(e =>
        {
            e.ToTable("AllowedNetworks");
            e.HasKey(x => x.Key);
            e.Property(x => x.Range).HasMaxLength(64);
            e.HasIndex(x => x.VaultId);
            e.HasIndex(x => x.ApiKeyKey);
            e.HasIndex(x => x.GroupKey);
            e.HasOne<Vault>().WithMany().HasForeignKey(x => x.VaultId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<ApiKey>().WithMany().HasForeignKey(x => x.ApiKeyKey).OnDelete(DeleteBehavior.Cascade);

            // A group that is still listed is not deleted from under what relies on it; the store refuses first.
            e.HasOne<NetworkGroup>().WithMany().HasForeignKey(x => x.GroupKey).OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<OidcProvider>(e =>
        {
            e.ToTable("OidcProviders");
            e.HasKey(x => x.Key);
            e.Property(x => x.Slug).HasMaxLength(32);
            e.HasIndex(x => x.Slug).IsUnique();
            e.Property(x => x.DisplayName).HasMaxLength(64);
            e.Property(x => x.Authority).HasMaxLength(512);
            e.Property(x => x.ClientId).HasMaxLength(256);
            e.Property(x => x.ProtectedClientSecret).HasMaxLength(2048);
            e.Property(x => x.Scopes).HasMaxLength(512);
            e.Property(x => x.UserNameClaim).HasMaxLength(64);
            e.Property(x => x.GroupsClaim).HasMaxLength(64);
            e.Property(x => x.AllowedEmailDomains).HasMaxLength(1024);
            e.Property(x => x.ApiAudiences).HasMaxLength(1024);
            e.Property(x => x.ApiRequiredClaims).HasMaxLength(1024);
        });

        modelBuilder.Entity<ExternalLogin>(e =>
        {
            e.ToTable("ExternalLogins");
            e.HasKey(x => x.Key);
            e.Property(x => x.Subject).HasMaxLength(256);
            e.Property(x => x.Email).HasMaxLength(256);
            e.HasIndex(x => new { x.ProviderKey, x.Subject }).IsUnique();
            e.HasIndex(x => x.UserKey);
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserKey).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<OidcProvider>().WithMany().HasForeignKey(x => x.ProviderKey).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<GroupProviderLink>(e =>
        {
            e.ToTable("GroupProviderLinks");
            e.HasKey(x => x.Key);
            e.Property(x => x.ProviderGroup).HasMaxLength(256);
            e.HasIndex(x => new { x.GroupKey, x.ProviderKey, x.ProviderGroup }).IsUnique();
            e.HasOne<Group>().WithMany().HasForeignKey(x => x.GroupKey).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<OidcProvider>().WithMany().HasForeignKey(x => x.ProviderKey).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<VaultAssignment>(e =>
        {
            e.ToTable("VaultAssignments");
            e.HasKey(x => x.Key);
            e.Property(x => x.Role).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.GrantedBy).HasMaxLength(256);
            e.HasIndex(x => x.VaultId);
            e.HasIndex(x => x.UserKey);
            e.HasIndex(x => x.GroupKey);
            e.HasOne<Vault>().WithMany().HasForeignKey(x => x.VaultId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserKey).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Group>().WithMany().HasForeignKey(x => x.GroupKey).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ApiKey>(e =>
        {
            e.ToTable("ApiKeys");
            e.HasKey(x => x.Key);
            e.Property(x => x.Label).HasMaxLength(128);
            e.Property(x => x.Prefix).HasMaxLength(16);
            e.Property(x => x.Hash).HasMaxLength(64);
            e.Property(x => x.MaxRole).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.LastUsedAddress).HasMaxLength(64);
            e.HasIndex(x => x.Prefix).IsUnique();
            e.HasIndex(x => x.UserKey);
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserKey).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<CertificateRecord>(e =>
        {
            e.ToTable("Certificates");
            e.HasKey(x => x.VersionId);
            e.Property(x => x.VersionId).ValueGeneratedNever();
            e.Property(x => x.Subject).HasMaxLength(1024);
            e.Property(x => x.Issuer).HasMaxLength(1024);
            e.Property(x => x.Serial).HasMaxLength(64);
            e.Property(x => x.Thumbprint).HasMaxLength(64);
            e.Property(x => x.Sha1Thumbprint).HasMaxLength(40);
            e.HasIndex(x => x.NotAfterUtc);
            e.HasOne<StoredVersion>().WithOne().HasForeignKey<CertificateRecord>(x => x.VersionId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuditEvent>(e =>
        {
            e.ToTable("Audit");
            e.Property(x => x.Code).HasMaxLength(64);
            e.Property(x => x.Severity).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Principal).HasMaxLength(256);
            e.Property(x => x.Vault).HasMaxLength(NameLength);
            e.Property(x => x.Secret).HasMaxLength(NameLength);
            e.Property(x => x.Slot).HasMaxLength(80);
            e.Property(x => x.Address).HasMaxLength(64);
            e.Property(x => x.Via).HasMaxLength(16);
            e.Property(x => x.Detail).HasMaxLength(2000);
            e.HasIndex(x => x.AtUtc);
            e.HasIndex(x => new { x.Code, x.AtUtc });
            e.HasIndex(x => x.VaultId);
            e.HasIndex(x => x.EntryId);
        });
    }

    private static void ConfigureSettings(ModelBuilder modelBuilder) => modelBuilder.Entity<AppSetting>(e =>
    {
        e.ToTable("Settings");
        e.HasKey(x => x.Key);
        e.Property(x => x.Key).HasMaxLength(64);
        e.Property(x => x.Value).HasMaxLength(2000);
    });

    private sealed class UtcConverter() : ValueConverter<DateTime, DateTime>(
        value => value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime(),
        value => DateTime.SpecifyKind(value, DateTimeKind.Utc));
}
