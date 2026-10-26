using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretHive.Infrastructure.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class ProviderTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AcceptApiTokens",
                table: "OidcProviders",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "ApiAudiences",
                table: "OidcProviders",
                type: "nvarchar(1024)",
                maxLength: 1024,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ApiRequiredClaims",
                table: "OidcProviders",
                type: "nvarchar(1024)",
                maxLength: 1024,
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AcceptApiTokens",
                table: "OidcProviders");

            migrationBuilder.DropColumn(
                name: "ApiAudiences",
                table: "OidcProviders");

            migrationBuilder.DropColumn(
                name: "ApiRequiredClaims",
                table: "OidcProviders");
        }
    }
}
