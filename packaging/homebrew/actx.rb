class Actx < Formula
  desc "Personal CLI context-compressor for AI agents"
  homepage "https://github.com/ampersante/actx"
  url "https://github.com/ampersante/actx/archive/refs/tags/v2.5.0.tar.gz"
  # Fill sha256 in the tap copy (homebrew-actx), not here: this file ships in
  # the same tarball, so its own hash cannot be self-contained.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  depends_on "python@3.14"

  def install
    libexec.install "actx"
    libexec.install "actx_lib"
    libexec.install "adapters"
    bin.install_symlink libexec/"actx"
  end

  test do
    system "#{bin}/actx", "--version"
  end
end
