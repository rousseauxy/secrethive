using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretHive.Infrastructure.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class SignInProviders : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "ProviderKey",
                table: "GroupMembers",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "OidcProviders",
                columns: table => new
                {
                    Key = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Slug = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Authority = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    ProtectedClientSecret = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    Scopes = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    UserNameClaim = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    GroupsClaim = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreateAccounts = table.Column<bool>(type: "INTEGER", nullable: false),
                    AllowedEmailDomains = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    Ordinal = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OidcProviders", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "ExternalLogins",
                columns: table => new
                {
                    Key = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    UserKey = table.Column<int>(type: "INTEGER", nullable: false),
                    ProviderKey = table.Column<int>(type: "INTEGER", nullable: false),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    LinkedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastUsedUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExternalLogins", x => x.Key);
                    table.ForeignKey(
                        name: "FK_ExternalLogins_OidcProviders_ProviderKey",
                        column: x => x.ProviderKey,
                        principalTable: "OidcProviders",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ExternalLogins_Users_UserKey",
                        column: x => x.UserKey,
                        principalTable: "Users",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "GroupProviderLinks",
                columns: table => new
                {
                    Key = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    GroupKey = table.Column<int>(type: "INTEGER", nullable: false),
                    ProviderKey = table.Column<int>(type: "INTEGER", nullable: false),
                    ProviderGroup = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GroupProviderLinks", x => x.Key);
                    table.ForeignKey(
                        name: "FK_GroupProviderLinks_Groups_GroupKey",
                        column: x => x.GroupKey,
                        principalTable: "Groups",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_GroupProviderLinks_OidcProviders_ProviderKey",
                        column: x => x.ProviderKey,
                        principalTable: "OidcProviders",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_GroupMembers_ProviderKey",
                table: "GroupMembers",
                column: "ProviderKey");

            migrationBuilder.CreateIndex(
                name: "IX_ExternalLogins_ProviderKey_Subject",
                table: "ExternalLogins",
                columns: new[] { "ProviderKey", "Subject" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ExternalLogins_UserKey",
                table: "ExternalLogins",
                column: "UserKey");

            migrationBuilder.CreateIndex(
                name: "IX_GroupProviderLinks_GroupKey_ProviderKey_ProviderGroup",
                table: "GroupProviderLinks",
                columns: new[] { "GroupKey", "ProviderKey", "ProviderGroup" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_GroupProviderLinks_ProviderKey",
                table: "GroupProviderLinks",
                column: "ProviderKey");

            migrationBuilder.CreateIndex(
                name: "IX_OidcProviders_Slug",
                table: "OidcProviders",
                column: "Slug",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_GroupMembers_OidcProviders_ProviderKey",
                table: "GroupMembers",
                column: "ProviderKey",
                principalTable: "OidcProviders",
                principalColumn: "Key");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_GroupMembers_OidcProviders_ProviderKey",
                table: "GroupMembers");

            migrationBuilder.DropTable(
                name: "ExternalLogins");

            migrationBuilder.DropTable(
                name: "GroupProviderLinks");

            migrationBuilder.DropTable(
                name: "OidcProviders");

            migrationBuilder.DropIndex(
                name: "IX_GroupMembers_ProviderKey",
                table: "GroupMembers");

            migrationBuilder.DropColumn(
                name: "ProviderKey",
                table: "GroupMembers");
        }
    }
}
