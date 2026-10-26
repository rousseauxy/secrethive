using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretHive.Infrastructure.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AuditEntryId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "EntryId",
                table: "Audit",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Audit_EntryId",
                table: "Audit",
                column: "EntryId");

            // The rows written before: each one naming a version gets the secret that holds it in the row's vault, so
            // its history stays its own after a rename or a move. Rows without a version keep only their names.
            migrationBuilder.Sql(SecretHive.Infrastructure.Persistence.AuditEntries.Backfill);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Audit_EntryId",
                table: "Audit");

            migrationBuilder.DropColumn(
                name: "EntryId",
                table: "Audit");
        }
    }
}
