using SecretHive.Cli;
using SecretHive.Cli.Bundles;
using SecretHive.Cli.Commands;
using SecretHive.Cli.Rendering;

namespace SecretHive.Unit.Tests;

public sealed class CheckStatusBundleTests
{
    private const string Manifest = """
        version: 1
        stack: shop
        vault: shop-prod
        targets:
          app:
            path: ${appdata}/shop/secrets
            owner: "999:999"
            restart: [shop]
            keys:
              Api__Token: api-token
          worker:
            path: ${appdata}/shop/secrets-worker
            owner: "1001:1001"
            restart: [shop-worker]
            keys:
              Api__Token: api-token
              Queue__Password: mail/queue-password
        """;

    private static Stack Rendered()
    {
        var stack = new Stack(Manifest);
        stack.Set("api-token", "generated-token");
        stack.Set("mail/queue-password", "generated-queue");
        stack.Run("render", "shop", "--host", "web-1");
        stack.Output.Clear();
        return stack;
    }

    [Fact]
    public void Check_passes_when_every_key_resolves_and_owners_match_the_running_containers()
    {
        using var stack = Rendered();
        stack.Containers.States["shop"] = new ContainerState(stack.Files.Now.AddHours(1), 999);

        Assert.Equal(App.Ok, stack.Run("check", "shop", "--host", "web-1"));

        Assert.Contains("ok       shop  3 keys in 2 targets", stack.Output.ToString());
    }

    [Fact]
    public void Check_fails_when_a_container_runs_as_another_uid_than_the_target_is_owned_by()
    {
        using var stack = Rendered();
        stack.Containers.States["shop-worker"] = new ContainerState(stack.Files.Now, 999);

        Assert.Equal(App.Refused, stack.Run("check", "shop", "--host", "web-1"));

        Assert.Contains("worker: shop-worker runs as uid 999, the target is owned by 1001", stack.Output.ToString());
    }

    [Fact]
    public void Status_is_in_step_after_a_render_and_a_restart()
    {
        using var stack = Rendered();
        stack.Containers.States["shop"] = new ContainerState(stack.Files.Now.AddMinutes(1), 999);

        Assert.Equal(App.Ok, stack.Run("status", "shop", "--host", "web-1"));

        Assert.Contains("in-step  shop", stack.Output.ToString());
    }

    [Fact]
    public void Status_reports_a_hand_edit_an_orphan_a_missing_file_and_a_pending_restart()
    {
        using var stack = Rendered();
        var app = stack.Target();
        stack.Files.DeleteFile(Path.Combine(app, "Api__Token"));
        stack.Files.SeedFile(Path.Combine(app, "Api__Token"), "edited-by-hand", 0, 0, 0x1A4);
        stack.Files.SeedFile(Path.Combine(app, "Left__Over"), "generated-old", 999, 999, Renderer.FileMode);
        stack.Files.DeleteFile(Path.Combine(stack.Target("secrets-worker"), "Queue__Password"));
        stack.Containers.States["shop"] = new ContainerState(stack.Files.Now.AddDays(-8), 999);

        Assert.Equal(App.Drift, stack.Run("status", "shop", "--host", "web-1"));

        var output = stack.Output.ToString();
        Assert.Contains("differs  app  Api__Token", output);
        Assert.Contains("drift    app  Api__Token  owner 0:0 -> 999:999, mode 0644 -> 0400", output);
        Assert.Contains("orphan   app  Left__Over", output);
        Assert.Contains("missing  worker  Queue__Password", output);
        Assert.Contains("restart-pending  app  shop", output);
    }

    [Fact]
    public void Import_adopts_the_files_on_disk_and_reports_which_references_hold_the_same_value()
    {
        using var stack = new Stack(Manifest);
        stack.Files.SeedDirectory(stack.Target(), 999, 999, Renderer.DirectoryMode);
        stack.Files.SeedDirectory(stack.Target("secrets-worker"), 1001, 1001, Renderer.DirectoryMode);
        stack.Files.SeedFile(Path.Combine(stack.Target(), "Api__Token"), "generated-shared", 999, 999, Renderer.FileMode);
        stack.Files.SeedFile(Path.Combine(stack.Target("secrets-worker"), "Api__Token"), "generated-shared", 1001, 1001, Renderer.FileMode);
        stack.Files.SeedFile(Path.Combine(stack.Target("secrets-worker"), "Queue__Password"), "generated-shared", 1001, 1001, Renderer.FileMode);

        Assert.Equal(App.Ok, stack.Run("bundle", "import", "shop", "--host", "web-1"));

        Assert.Contains("imported   shop-prod/api-token", stack.Output.ToString());
        Assert.Contains("identical  mail/queue-password = shop-prod/api-token", stack.Output.ToString());
        stack.Output.Clear();
        var rendered = stack.Run("render", "shop", "--host", "web-1");
        Assert.True(rendered == App.Ok, stack.Output.ToString());
        Assert.Equal(App.Ok, stack.Run("bundle", "import", "shop", "--host", "web-1"));
        Assert.Contains("unchanged  shop-prod/api-token", stack.Output.ToString());
    }

    [Fact]
    public void Import_refuses_two_keys_that_share_a_reference_but_differ_on_disk()
    {
        using var stack = new Stack(Manifest);
        stack.Files.SeedFile(Path.Combine(stack.Target(), "Api__Token"), "generated-a", 999, 999, Renderer.FileMode);
        stack.Files.SeedFile(Path.Combine(stack.Target("secrets-worker"), "Api__Token"), "generated-b", 1001, 1001, Renderer.FileMode);
        stack.Files.SeedFile(Path.Combine(stack.Target("secrets-worker"), "Queue__Password"), "generated-c", 1001, 1001, Renderer.FileMode);

        Assert.Equal(App.Refused, stack.Run("bundle", "import", "shop", "--host", "web-1"));

        Assert.Contains("worker Api__Token and app Api__Token share shop-prod/api-token but hold different content", stack.Output.ToString());
        Assert.False(File.Exists(stack.BundlePath));
    }

    [Fact]
    public void Prune_drops_bundle_entries_the_manifest_no_longer_references()
    {
        using var stack = Rendered();
        stack.Set("shop-prod/retired", "generated-retired");
        stack.Output.Clear();

        Assert.Equal(App.Ok, stack.Run("bundle", "prune", "shop", "--host", "web-1"));

        Assert.Equal("removed    shop-prod/retired", stack.Output.ToString().Trim());
        Assert.DoesNotContain("retired", File.ReadAllText(stack.BundlePath));
    }

    [Fact]
    public void An_entry_moved_to_another_reference_does_not_open()
    {
        using var stack = Rendered();
        var bundle = Bundle.LoadOrEmpty(stack.BundlePath, "web-1", "shop");
        var token = bundle.Find("shop-prod/api-token")!;
        bundle.Set(token with { Reference = "mail/queue-password" });
        bundle.Save(stack.BundlePath);

        var e = Record.Exception(() => stack.Run("render", "shop", "--host", "web-1"));

        Assert.Null(e);
        Assert.Contains("mail/queue-password: cannot be opened with this host's key, or the entry was altered", stack.Output.ToString());
    }

    [Fact]
    public void The_bundle_is_one_line_per_reference_and_holds_no_value()
    {
        using var stack = Rendered();

        var lines = File.ReadAllLines(stack.BundlePath);

        Assert.Equal(3, lines.Length);
        Assert.StartsWith("""{"secrethive-bundle":1,"host":"web-1","stack":"shop"}""", lines[0]);
        Assert.StartsWith("""{"ref":"mail/queue-password",""", lines[1]);
        Assert.StartsWith("""{"ref":"shop-prod/api-token",""", lines[2]);
        Assert.DoesNotContain("generated", File.ReadAllText(stack.BundlePath));
    }

    [Fact]
    public void No_command_ever_prints_a_value()
    {
        using var stack = new Stack(Manifest);
        stack.Set("api-token", "generated-token");
        stack.Set("mail/queue-password", "generated-queue");
        stack.Run("render", "shop", "--host", "web-1", "--dry-run");
        stack.Run("render", "shop", "--host", "web-1");
        stack.Files.DeleteFile(Path.Combine(stack.Target(), "Api__Token"));
        stack.Files.SeedFile(Path.Combine(stack.Target(), "Api__Token"), "edited-by-hand", 0, 0, 0x1A4);
        stack.Run("status", "shop", "--host", "web-1");
        stack.Run("check", "shop", "--host", "web-1");
        stack.Run("bundle", "import", "shop", "--host", "web-1");
        stack.Run("bundle", "prune", "shop", "--host", "web-1");
        stack.Pipe("generated-bad\n");
        stack.Run("bundle", "set", "shop", "api-token", "--host", "web-1");

        var output = stack.Output.ToString();
        Assert.DoesNotContain("generated-", output);
        Assert.DoesNotContain("edited-by-hand", output);
    }

    [Theory]
    [InlineData("Server=db;Password=x")]
    [InlineData("a/b/c/d")]
    [InlineData("with space")]
    [InlineData("vault/name#")]
    public void Things_that_are_not_references_are_refused(string text) =>
        Assert.Throws<InputException>(() => SecretReference.Parse(text, "vault"));

    [Fact]
    public void A_reference_keeps_its_vault_version_and_part()
    {
        var reference = SecretReference.Parse("edge/wildcard/3f2a#pfx", null);

        Assert.Equal(("edge", "wildcard", "3f2a", "pfx"), (reference.Vault, reference.Name, reference.Version, reference.Part));
        Assert.Equal("edge/wildcard#pfx", reference.BundleKey);
        Assert.Equal("shop-prod/token", SecretReference.Parse("token", "shop-prod").BundleKey);
    }
}

public sealed class DockerCliTests
{
    [Fact]
    public void A_missing_container_runtime_is_refused_by_name_instead_of_read_as_nothing_running() =>
        Assert.Contains(
            "could not be started",
            Assert.Throws<SecretHive.Cli.InputException>(() => new DockerCli(["secrethive-no-such-runtime"]).Running("shop")).Message);
}
