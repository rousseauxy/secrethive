using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretHive.Infrastructure.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Audit",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    AtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Code = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Severity = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    Principal = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Vault = table.Column<string>(type: "nvarchar(127)", maxLength: 127, nullable: true),
                    Secret = table.Column<string>(type: "nvarchar(127)", maxLength: 127, nullable: true),
                    VersionId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Slot = table.Column<string>(type: "nvarchar(80)", maxLength: 80, nullable: true),
                    Address = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    Via = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: true),
                    Detail = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Audit", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Settings",
                columns: table => new
                {
                    Key = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Value = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Settings", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "Values",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Kind = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    ContentType = table.Column<string>(type: "nvarchar(127)", maxLength: 127, nullable: true),
                    NotBeforeUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CurrentVersionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Values", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Vaults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(127)", maxLength: 127, nullable: false),
                    NameKey = table.Column<string>(type: "nvarchar(127)", maxLength: 127, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PurgeProtection = table.Column<bool>(type: "bit", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vaults", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Versions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ValueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Number = table.Column<int>(type: "int", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedBy = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    DataKeyId = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    DataKey = table.Column<byte[]>(type: "varbinary(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Versions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Versions_Values_ValueId",
                        column: x => x.ValueId,
                        principalTable: "Values",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Entries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VaultId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ValueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(127)", maxLength: 127, nullable: false),
                    NameKey = table.Column<string>(type: "nvarchar(127)", maxLength: 127, nullable: false),
                    BinKey = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Enabled = table.Column<bool>(type: "bit", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DeletedUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    DeletedBy = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    CopiedFrom = table.Column<string>(type: "nvarchar(300)", maxLength: 300, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Entries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Entries_Values_ValueId",
                        column: x => x.ValueId,
                        principalTable: "Values",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Entries_Vaults_VaultId",
                        column: x => x.VaultId,
                        principalTable: "Vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Certificates",
                columns: table => new
                {
                    VersionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Subject = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    Issuer = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    Serial = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Thumbprint = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Sha1Thumbprint = table.Column<string>(type: "nvarchar(40)", maxLength: 40, nullable: false),
                    NotBeforeUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    NotAfterUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    AlternativeNames = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Certificates", x => x.VersionId);
                    table.ForeignKey(
                        name: "FK_Certificates_Versions_VersionId",
                        column: x => x.VersionId,
                        principalTable: "Versions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VersionItems",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VersionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Slot = table.Column<string>(type: "nvarchar(80)", maxLength: 80, nullable: false),
                    FieldType = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: true),
                    FileName = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    Content = table.Column<byte[]>(type: "varbinary(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VersionItems", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VersionItems_Versions_VersionId",
                        column: x => x.VersionId,
                        principalTable: "Versions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EntryFields",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EntryId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(63)", maxLength: 63, nullable: false),
                    Type = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    Value = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EntryFields", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EntryFields_Entries_EntryId",
                        column: x => x.EntryId,
                        principalTable: "Entries",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Audit_AtUtc",
                table: "Audit",
                column: "AtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Audit_Code_AtUtc",
                table: "Audit",
                columns: new[] { "Code", "AtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_NotAfterUtc",
                table: "Certificates",
                column: "NotAfterUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Entries_ValueId",
                table: "Entries",
                column: "ValueId");

            migrationBuilder.CreateIndex(
                name: "IX_Entries_VaultId_NameKey_BinKey",
                table: "Entries",
                columns: new[] { "VaultId", "NameKey", "BinKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EntryFields_EntryId_Name",
                table: "EntryFields",
                columns: new[] { "EntryId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Vaults_NameKey",
                table: "Vaults",
                column: "NameKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VersionItems_VersionId_Slot",
                table: "VersionItems",
                columns: new[] { "VersionId", "Slot" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Versions_ValueId_Number",
                table: "Versions",
                columns: new[] { "ValueId", "Number" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Audit");

            migrationBuilder.DropTable(
                name: "Certificates");

            migrationBuilder.DropTable(
                name: "EntryFields");

            migrationBuilder.DropTable(
                name: "Settings");

            migrationBuilder.DropTable(
                name: "VersionItems");

            migrationBuilder.DropTable(
                name: "Entries");

            migrationBuilder.DropTable(
                name: "Versions");

            migrationBuilder.DropTable(
                name: "Vaults");

            migrationBuilder.DropTable(
                name: "Values");
        }
    }
}
