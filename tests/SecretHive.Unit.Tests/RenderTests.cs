using SecretHive.Cli.Commands;
using SecretHive.Cli.Rendering;

namespace SecretHive.Unit.Tests;

public sealed class RenderTests
{
    private const string Manifest = """
        version: 1
        stack: shop
        vault: shop-prod
        targets:
          app:
            path: ${appdata}/shop/secrets
            owner: "999:999"
            restart: [shop, shop-worker]
            keys:
              ConnectionStrings__Default: sql-app-connection
              Api__Token: api-token
        """;

    private static Stack Sealed()
    {
        var stack = new Stack(Manifest);
        stack.Set("sql-app-connection", "Server=db;Password=generated-one");
        stack.Set("api-token", "generated-token");
        stack.Output.Clear();
        return stack;
    }

    [Fact]
    public void First_render_creates_every_key_with_owner_and_mode_and_names_what_to_restart()
    {
        using var stack = Sealed();

        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1"));

        Assert.Equal("Server=db;Password=generated-one", stack.Files.Text(Path.Combine(stack.Target(), "ConnectionStrings__Default")));
        var file = stack.Files.Stat(Path.Combine(stack.Target(), "Api__Token"))!;
        Assert.Equal((999u, 999u, Renderer.FileMode), (file.Uid, file.Gid, file.Mode));
        var directory = stack.Files.Stat(stack.Target())!;
        Assert.Equal((999u, 999u, Renderer.DirectoryMode), (directory.Uid, directory.Gid, directory.Mode));
        var lines = stack.Output.ToString().Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains("created  app  ConnectionStrings__Default", lines);
        Assert.Contains("restart  shop", lines);
        Assert.Contains("restart  shop-worker", lines);
    }

    [Fact]
    public void Second_render_changes_nothing_and_rewrites_nothing()
    {
        using var stack = Sealed();
        stack.Run("render", "shop", "--host", "web-1");
        var writes = stack.Files.Writes;
        stack.Output.Clear();

        Assert.Equal(App.Ok, stack.Run("render", "shop", "--host", "web-1"));

        Assert.Equal(writes, stack.Files.Writes);
        Assert.Equal("", stack.Output.ToString());
    }

    [Fact]
    public void A_changed_value_rewrites_only_that_file()
    {
        using var stack = Sealed();
        stack.Run("render", "shop", "--host", "web-1");
        var writes = stack.Files.Writes;
        stack.Set("api-token", "generated-token-2");
        stack.Output.Clear();

        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1"));

        Assert.Equal(writes + 1, stack.Files.Writes);
        Assert.Equal("generated-token-2", stack.Files.Text(Path.Combine(stack.Target(), "Api__Token")));
        Assert.Contains("changed  app  Api__Token", stack.Output.ToString());
        Assert.DoesNotContain("ConnectionStrings__Default", stack.Output.ToString());
    }

    [Fact]
    public void Nothing_temporary_ever_exists_inside_the_target()
    {
        using var stack = Sealed();

        stack.Run("render", "shop", "--host", "web-1");

        var inside = stack.Files.EverCreated
            .Where(path => path.StartsWith(stack.Target() + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal);
        Assert.Equal(["Api__Token", "ConnectionStrings__Default"], inside);
        Assert.False(stack.Files.Exists(stack.Target() + ".secrethive-staging"));
    }

    [Fact]
    public void A_file_the_manifest_does_not_declare_is_pruned_and_other_entries_are_left_alone()
    {
        using var stack = Sealed();
        stack.Run("render", "shop", "--host", "web-1");
        stack.Files.SeedFile(Path.Combine(stack.Target(), "Old__Key"), "generated-old", 999, 999, Renderer.FileMode);
        stack.Files.SeedOther(Path.Combine(stack.Target(), "a-link"));
        stack.Output.Clear();

        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1"));

        Assert.False(stack.Files.Exists(Path.Combine(stack.Target(), "Old__Key")));
        Assert.True(stack.Files.Exists(Path.Combine(stack.Target(), "a-link")));
        Assert.Contains("pruned   app  Old__Key", stack.Output.ToString());
        Assert.Contains("foreign  app  a-link", stack.Output.ToString());
    }

    [Fact]
    public void A_wrong_owner_is_repaired_without_rewriting_the_file()
    {
        using var stack = Sealed();
        stack.Run("render", "shop", "--host", "web-1");
        var writes = stack.Files.Writes;
        stack.Files.SetOwner(Path.Combine(stack.Target(), "Api__Token"), 0, 0);
        stack.Output.Clear();

        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1"));

        Assert.Equal(writes, stack.Files.Writes);
        Assert.Equal(999u, stack.Files.Stat(Path.Combine(stack.Target(), "Api__Token"))!.Uid);
        Assert.Contains("fixed    app  Api__Token  owner 0:0 -> 999:999", stack.Output.ToString());
    }

    [Fact]
    public void A_dry_run_writes_nothing_and_shows_the_owner_and_mode_each_file_would_get()
    {
        using var stack = Sealed();

        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1", "--dry-run"));

        Assert.False(stack.Files.Exists(stack.Target()));
        Assert.Equal(0, stack.Files.Writes);
        Assert.Contains("created  app  Api__Token  999:999 0400", stack.Output.ToString());
    }

    [Theory]
    [InlineData("generated\n", "ends with whitespace")]
    [InlineData(" generated", "starts with whitespace")]
    [InlineData("", "is empty")]
    public void A_value_that_would_break_the_application_is_refused_when_it_is_set(string value, string reason)
    {
        using var stack = new Stack(Manifest);
        stack.Pipe(value);

        Assert.Equal(App.Refused, stack.Run("bundle", "set", "shop", "api-token", "--host", "web-1"));

        Assert.Contains(reason, stack.Output.ToString());
        Assert.False(File.Exists(stack.BundlePath));
    }

    [Fact]
    public void One_unresolved_key_refuses_the_whole_render_before_anything_is_written()
    {
        using var stack = new Stack(Manifest);
        stack.Set("api-token", "generated-token");

        Assert.Equal(App.Refused, stack.Run("render", "shop", "--host", "web-1"));

        Assert.Equal(0, stack.Files.Writes);
        Assert.False(stack.Files.Exists(stack.Target()));
        Assert.Contains("app ConnectionStrings__Default: shop-prod/sql-app-connection is not in the bundle", stack.Output.ToString());
    }

    private const string EnvManifest = """
        version: 1
        stack: shop
        vault: shop-prod
        targets:
          compose:
            path: ${appdata}/shop/compose-secrets
            owner: "0:0"
            format: env
            restart: []
            keys:
              QUEUE_PASSWORD: queue-password
              UPSTREAM_BYPASS_KEY: shared/upstream-bypass-key
              ODD_ONE: odd-one
        """;

    [Fact]
    public void An_env_target_is_one_file_of_quoted_lines_that_compose_reads_as_they_are()
    {
        using var stack = new Stack(EnvManifest);
        stack.Set("queue-password", "generated$pass with # and spaces");
        stack.Set("shared/upstream-bypass-key", "generated-bypass");
        stack.Set("odd-one", "it's generated");
        stack.Output.Clear();

        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1"));

        var directory = Path.Combine(stack.AppData, "shop", "compose-secrets");
        Assert.Equal(
            "ODD_ONE='it\\'s generated'\nQUEUE_PASSWORD='generated$pass with # and spaces'\nUPSTREAM_BYPASS_KEY='generated-bypass'\n",
            stack.Files.Text(Path.Combine(directory, "secrets.env")));
        var file = stack.Files.Stat(Path.Combine(directory, "secrets.env"))!;
        Assert.Equal((0u, 0u, Renderer.FileMode), (file.Uid, file.Gid, file.Mode));
        Assert.Single(stack.Files.List(directory));
        Assert.Contains("created  compose  secrets.env", stack.Output.ToString());
        Assert.DoesNotContain("generated", stack.Output.ToString(), StringComparison.Ordinal);

        // In step, and a changed value is seen as that one file differing.
        Assert.Equal(App.Ok, stack.Run("render", "shop", "--host", "web-1"));
        Assert.Equal(App.Ok, stack.Run("status", "shop", "--host", "web-1"));
        stack.Set("queue-password", "generated-another");
        stack.Output.Clear();
        Assert.Equal(App.Drift, stack.Run("status", "shop", "--host", "web-1"));
        Assert.Contains("differs  compose  secrets.env", stack.Output.ToString());

        // A value with a line break cannot be a line of an env file.
        stack.Pipe("generated\nsecond line");
        Assert.Equal(App.Ok, stack.Run("bundle", "set", "shop", "odd-one", "--host", "web-1"));
        stack.Output.Clear();
        Assert.Equal(App.Refused, stack.Run("render", "shop", "--host", "web-1"));
        Assert.Contains("compose ODD_ONE: the value holds a line break", stack.Output.ToString());

        // A backslash at the end would escape the closing quote and swallow the next line; one before a quote comes
        // back without the backslash. Compose v5 was measured on both; neither is written.
        foreach (var value in new[] { "generated-ends-with\\", "generated\\'quoted" })
        {
            stack.Set("odd-one", value);
            stack.Output.Clear();
            Assert.Equal(App.Refused, stack.Run("render", "shop", "--host", "web-1"));
            Assert.Contains("compose ODD_ONE: the value has a backslash at its end or before a quote", stack.Output.ToString());
            Assert.DoesNotContain("generated", stack.Output.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Import_takes_the_variables_of_an_env_target_out_of_the_stacks_dot_env_and_refuses_what_compose_would_rewrite()
    {
        using var stack = new Stack(EnvManifest);
        var env = Path.Combine(stack.Repository, "shop", ".env");
        File.WriteAllText(env, "# settings\nTZ=Etc/UTC\nQUEUE_PASSWORD=generated-plain\nUPSTREAM_BYPASS_KEY='generated $quoted # kept'\nODD_ONE=\"generated-in-double\"\n");

        Assert.Equal(App.Ok, stack.Run("bundle", "import", "shop", "--host", "web-1"));
        Assert.DoesNotContain("generated", stack.Output.ToString(), StringComparison.Ordinal);
        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1"));
        Assert.Equal(
            "ODD_ONE='generated-in-double'\nQUEUE_PASSWORD='generated-plain'\nUPSTREAM_BYPASS_KEY='generated $quoted # kept'\n",
            stack.Files.Text(Path.Combine(stack.AppData, "shop", "compose-secrets", "secrets.env")));

        // Unquoted with a $ in it, Compose would substitute: not guessed at, and nothing is sealed from this run.
        File.WriteAllText(env, "QUEUE_PASSWORD=generated$HOME\nUPSTREAM_BYPASS_KEY=generated-bypass\n");
        stack.Output.Clear();
        Assert.Equal(App.Refused, stack.Run("bundle", "import", "shop", "--host", "web-1"));
        var said = stack.Output.ToString();
        Assert.Contains("compose QUEUE_PASSWORD: in .env it is unquoted with a $", said);
        Assert.Contains("compose ODD_ONE: .env has no such variable", said);
        Assert.DoesNotContain("generated", said, StringComparison.Ordinal);
    }

    [Fact]
    public void A_checkout_of_another_host_is_refused()
    {
        using var stack = Sealed();

        Assert.Equal(App.Refused, stack.Run("render", "shop", "--host", "prod"));

        Assert.Contains("this checkout is host 'web-1', not 'prod'", stack.Output.ToString());
        Assert.Equal(0, stack.Files.Writes);
    }

    [Fact]
    public void A_target_outside_appdata_is_refused()
    {
        using var stack = new Stack(Manifest.Replace("${appdata}/shop/secrets", "${appdata}/../elsewhere", StringComparison.Ordinal));

        Assert.Equal(App.Refused, stack.Run("render", "shop", "--host", "web-1"));

        Assert.Contains("must be a directory under", stack.Output.ToString());
    }

    [Fact]
    public void A_value_pasted_into_the_manifest_is_refused_as_a_reference()
    {
        using var stack = new Stack(Manifest.Replace("api-token", "Server=db;Password=pasted", StringComparison.Ordinal));

        Assert.Equal(App.Refused, stack.Run("check", "shop", "--host", "web-1"));

        Assert.Contains("is not a reference", stack.Output.ToString());
    }

    [Fact]
    public void An_unknown_manifest_key_is_an_error_not_a_default()
    {
        using var stack = new Stack(Manifest.Replace("owner:", "ownr:", StringComparison.Ordinal));

        Assert.Equal(App.Refused, stack.Run("check", "shop", "--host", "web-1"));

        Assert.Contains("'owner' is missing", stack.Output.ToString());
    }

    [Fact]
    public void Rendering_needs_host_access_and_says_so()
    {
        using var stack = Sealed();
        stack.HostAccessProblem = "run as root";

        Assert.Equal(App.Refused, stack.Run("render", "shop", "--host", "web-1"));

        Assert.Contains("run as root", stack.Output.ToString());
    }
}
