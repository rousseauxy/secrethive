using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretHive.Infrastructure.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class Access : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Groups",
                columns: table => new
                {
                    Key = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 127, nullable: false),
                    NameLower = table.Column<string>(type: "TEXT", maxLength: 127, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Groups", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "GroupMembers",
                columns: table => new
                {
                    Key = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    GroupKey = table.Column<int>(type: "INTEGER", nullable: false),
                    UserKey = table.Column<int>(type: "INTEGER", nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GroupMembers", x => x.Key);
                    table.ForeignKey(
                        name: "FK_GroupMembers_Groups_GroupKey",
                        column: x => x.GroupKey,
                        principalTable: "Groups",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_GroupMembers_Users_UserKey",
                        column: x => x.UserKey,
                        principalTable: "Users",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VaultAssignments",
                columns: table => new
                {
                    Key = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    VaultId = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserKey = table.Column<int>(type: "INTEGER", nullable: true),
                    GroupKey = table.Column<int>(type: "INTEGER", nullable: true),
                    Role = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    GrantedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    GrantedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VaultAssignments", x => x.Key);
                    table.ForeignKey(
                        name: "FK_VaultAssignments_Groups_GroupKey",
                        column: x => x.GroupKey,
                        principalTable: "Groups",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_VaultAssignments_Users_UserKey",
                        column: x => x.UserKey,
                        principalTable: "Users",
                        principalColumn: "Key",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_VaultAssignments_Vaults_VaultId",
                        column: x => x.VaultId,
                        principalTable: "Vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_GroupMembers_GroupKey_UserKey",
                table: "GroupMembers",
                columns: new[] { "GroupKey", "UserKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_GroupMembers_UserKey",
                table: "GroupMembers",
                column: "UserKey");

            migrationBuilder.CreateIndex(
                name: "IX_Groups_NameLower",
                table: "Groups",
                column: "NameLower",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VaultAssignments_GroupKey",
                table: "VaultAssignments",
                column: "GroupKey");

            migrationBuilder.CreateIndex(
                name: "IX_VaultAssignments_UserKey",
                table: "VaultAssignments",
                column: "UserKey");

            migrationBuilder.CreateIndex(
                name: "IX_VaultAssignments_VaultId",
                table: "VaultAssignments",
                column: "VaultId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "GroupMembers");

            migrationBuilder.DropTable(
                name: "VaultAssignments");

            migrationBuilder.DropTable(
                name: "Groups");
        }
    }
}
