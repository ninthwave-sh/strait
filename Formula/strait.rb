class Strait < Formula
  desc "HTTPS proxy with Cedar policy evaluation, credential injection, and audit logging"
  homepage "https://github.com/ninthwave-sh/strait"
  license "MIT"

  # TODO: Update with actual release URL and SHA after first release
  # url "https://github.com/ninthwave-sh/strait/releases/download/v0.1.0/strait-#{arch}-apple-darwin.tar.gz"
  # sha256 ""

  def install
    bin.install "strait"
  end

  test do
    assert_match "strait", shell_output("#{bin}/strait --version")
  end
end
