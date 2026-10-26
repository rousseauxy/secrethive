using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretHive.Infrastructure.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class Keys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsService",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "ApiKeys",
                columns: table => new
                {
                    Key = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserKey = table.Column<int>(type: "int", nullable: false),
                    Label = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Prefix = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    Hash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    VaultId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    MaxRole = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: true),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RevokedUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    LastUsedUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    LastUsedAddress = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiKeys", x => x.Key);
                    table.ForeignKey(
                        name: "FK_ApiKeys_Users_UserKey",
                        column: x => x.UserKey,
                        principalTable: "Users",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ApiKeys_Prefix",
                table: "ApiKeys",
                column: "Prefix",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApiKeys_UserKey",
                table: "ApiKeys",
                column: "UserKey");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ApiKeys");

            migrationBuilder.DropColumn(
                name: "IsService",
                table: "Users");
        }
    }
}
