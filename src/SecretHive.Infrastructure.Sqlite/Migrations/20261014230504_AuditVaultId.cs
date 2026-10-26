using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretHive.Infrastructure.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AuditVaultId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "VaultId",
                table: "Audit",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Audit_VaultId",
                table: "Audit",
                column: "VaultId");

            // The rows written before: each one about a vault that still exists gets that vault's id, so its activity
            // stays its own after a rename. Rows about a vault deleted since keep only the name they were written with.
            migrationBuilder.Sql(SecretHive.Infrastructure.Persistence.AuditVaults.Backfill);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Audit_VaultId",
                table: "Audit");

            migrationBuilder.DropColumn(
                name: "VaultId",
                table: "Audit");
        }
    }
}
