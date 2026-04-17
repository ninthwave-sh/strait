class Strait < Formula
  desc "Network policy layer for AI-agent devcontainers"
  homepage "https://github.com/ninthwave-io/strait"
  license "Apache-2.0"
  head "https://github.com/ninthwave-io/strait.git", branch: "main"

  # Pre-release: strait has not cut its first versioned Homebrew release
  # yet, so the formula builds from HEAD. The release URL and sha256 go
  # here once the first tarball is published.
  # url "https://github.com/ninthwave-io/strait/releases/download/vX.Y.Z/strait-X.Y.Z.tar.gz"
  # sha256 ""

  depends_on "rust" => :build

  def install
    # Build the whole workspace so strait (policy tooling), strait-host
    # (control plane), and strait-agent (in-container proxy) all ship
    # from the same install. `cargo install` can only target one crate
    # at a time, so call it once per workspace member and use --root so
    # the binaries land in the formula's bin dir.
    system "cargo", "install", *std_cargo_args, "--path", "."
    system "cargo", "install", *std_cargo_args, "--path", "host"
    system "cargo", "install", *std_cargo_args, "--path", "agent"

    # Ship the plist template and config seed next to the formula so
    # manual installs and `brew services` users can look them up under
    # $(brew --prefix strait)/share/strait/.
    pkgshare.install "packaging/macos/io.ninthwave.strait.host.plist"
    pkgshare.install "packaging/macos/setup-socket-dir.sh"
    pkgshare.install "packaging/host.toml.example"
  end

  # `brew services start strait` writes this plist to
  # ~/Library/LaunchAgents/io.ninthwave.strait.host.plist (plist_name
  # overrides Homebrew's default homebrew.mxcl.* label) so the launchd
  # entry matches the path documented in packaging/macos/.
  service do
    run [opt_bin/"strait-host", "serve"]
    run_type :immediate
    keep_alive true
    log_path var/"log/strait-host.log"
    error_log_path var/"log/strait-host.log"
    environment_variables RUST_LOG: "info"
    plist_name "io.ninthwave.strait.host"
  end

  def post_install
    # Seed ~/.config/strait/host.toml on first install so operators have
    # a documented template to edit. Leave an existing file alone; the
    # user may have customized it.
    config_dir = Pathname.new(Dir.home) / ".config" / "strait"
    config_dir.mkpath
    target = config_dir / "host.toml"
    return if target.exist?

    target.write (pkgshare / "host.toml.example").read
    target.chmod 0644
  end

  def caveats
    <<~EOS
      strait-host binds a Unix socket at /var/run/strait/host.sock by
      default. /var/run is owned by root on macOS, so run this once to
      grant the socket directory to your user before starting the
      service:

          sudo #{opt_pkgshare}/setup-socket-dir.sh

      Then start the host control plane:

          brew services start strait

      Logs land in #{var}/log/strait-host.log. The default config was
      seeded at ~/.config/strait/host.toml; edit it to override
      defaults.
    EOS
  end

  test do
    assert_match "strait-host", shell_output("#{bin}/strait-host --version")
    assert_match "strait", shell_output("#{bin}/strait --version")
    assert_predicate pkgshare/"io.ninthwave.strait.host.plist", :exist?
    assert_predicate pkgshare/"host.toml.example", :exist?
  end
end
