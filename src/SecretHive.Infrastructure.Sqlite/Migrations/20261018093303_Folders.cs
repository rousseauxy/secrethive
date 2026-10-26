using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretHive.Infrastructure.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class Folders : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "FolderId",
                table: "Vaults",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Folders",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 127, nullable: false),
                    NameKey = table.Column<string>(type: "TEXT", maxLength: 127, nullable: false),
                    ParentId = table.Column<Guid>(type: "TEXT", nullable: true),
                    Description = table.Column<string>(type: "TEXT", nullable: true),
                    CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Folders", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "FolderAssignments",
                columns: table => new
                {
                    Key = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    FolderId = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserKey = table.Column<int>(type: "INTEGER", nullable: true),
                    GroupKey = table.Column<int>(type: "INTEGER", nullable: true),
                    Role = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    GrantedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    GrantedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FolderAssignments", x => x.Key);
                    table.ForeignKey(
                        name: "FK_FolderAssignments_Folders_FolderId",
                        column: x => x.FolderId,
                        principalTable: "Folders",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_FolderAssignments_Groups_GroupKey",
                        column: x => x.GroupKey,
                        principalTable: "Groups",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_FolderAssignments_Users_UserKey",
                        column: x => x.UserKey,
                        principalTable: "Users",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Vaults_FolderId",
                table: "Vaults",
                column: "FolderId");

            migrationBuilder.CreateIndex(
                name: "IX_FolderAssignments_FolderId",
                table: "FolderAssignments",
                column: "FolderId");

            migrationBuilder.CreateIndex(
                name: "IX_FolderAssignments_GroupKey",
                table: "FolderAssignments",
                column: "GroupKey");

            migrationBuilder.CreateIndex(
                name: "IX_FolderAssignments_UserKey",
                table: "FolderAssignments",
                column: "UserKey");

            migrationBuilder.CreateIndex(
                name: "IX_Folders_NameKey",
                table: "Folders",
                column: "NameKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Folders_ParentId",
                table: "Folders",
                column: "ParentId");

            migrationBuilder.AddForeignKey(
                name: "FK_Vaults_Folders_FolderId",
                table: "Vaults",
                column: "FolderId",
                principalTable: "Folders",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Vaults_Folders_FolderId",
                table: "Vaults");

            migrationBuilder.DropTable(
                name: "FolderAssignments");

            migrationBuilder.DropTable(
                name: "Folders");

            migrationBuilder.DropIndex(
                name: "IX_Vaults_FolderId",
                table: "Vaults");

            migrationBuilder.DropColumn(
                name: "FolderId",
                table: "Vaults");
        }
    }
}
