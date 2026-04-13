class Strait < Formula
  desc "Policy platform for AI agents - Cedar policy over network, filesystem, and process access"
  homepage "https://github.com/ninthwave-io/strait"
  license "Apache-2.0"

  # TODO: Update with actual release URL and SHA after first release
  # url "https://github.com/ninthwave-io/strait/releases/download/v0.1.0/strait-#{arch}-apple-darwin.tar.gz"
  # sha256 ""

  def install
    bin.install "strait"
  end

  test do
    assert_match "strait", shell_output("#{bin}/strait --version")
  end
end
