using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretHive.Infrastructure.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class Networks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "NetworkGroups",
                columns: table => new
                {
                    Key = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    NameLower = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Ranges = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkGroups", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "AllowedNetworks",
                columns: table => new
                {
                    Key = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    VaultId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ApiKeyKey = table.Column<int>(type: "INTEGER", nullable: true),
                    GroupKey = table.Column<int>(type: "INTEGER", nullable: true),
                    Range = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AllowedNetworks", x => x.Key);
                    table.ForeignKey(
                        name: "FK_AllowedNetworks_ApiKeys_ApiKeyKey",
                        column: x => x.ApiKeyKey,
                        principalTable: "ApiKeys",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AllowedNetworks_NetworkGroups_GroupKey",
                        column: x => x.GroupKey,
                        principalTable: "NetworkGroups",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_AllowedNetworks_Vaults_VaultId",
                        column: x => x.VaultId,
                        principalTable: "Vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AllowedNetworks_ApiKeyKey",
                table: "AllowedNetworks",
                column: "ApiKeyKey");

            migrationBuilder.CreateIndex(
                name: "IX_AllowedNetworks_GroupKey",
                table: "AllowedNetworks",
                column: "GroupKey");

            migrationBuilder.CreateIndex(
                name: "IX_AllowedNetworks_VaultId",
                table: "AllowedNetworks",
                column: "VaultId");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkGroups_NameLower",
                table: "NetworkGroups",
                column: "NameLower",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AllowedNetworks");

            migrationBuilder.DropTable(
                name: "NetworkGroups");
        }
    }
}
