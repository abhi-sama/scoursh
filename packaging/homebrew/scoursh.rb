class Scoursh < Formula
  desc "Egress-restricted security scanner for source, endpoints, and AWS"
  homepage "https://github.com/abhi-sama/scoursh"
  # RELEASE_JOB: replace both @VERSION@ tokens with the tagged release version.
  url "https://github.com/abhi-sama/scoursh/releases/download/v@VERSION@/scoursh-@VERSION@.tar.gz"
  # RELEASE_JOB: replace with the SHA-256 of those exact release-tarball bytes.
  sha256 "@SHA256@"
  license "Apache-2.0"

  livecheck do
    url :stable
    strategy :github_latest
  end

  # macOS ships bash 3.2; scoursh requires bash >= 4.2.
  depends_on "bash"

  # openssl enables TLS/JWT checks, git enables `sast --history`, and sqlite3
  # enables RPM image enumeration. They remain optional system tools: missing
  # tools produce declared coverage reductions, so this formula does not force
  # them onto users who do not select those scan capabilities.

  def install
    libexec.install Dir["*"]
    # Dir["*"] excludes dotfiles. This marker selects scoursh's installed-copy
    # XDG/SCOURSH_HOME state layout; omit it and Homebrew upgrades lose state.
    libexec.install ".scoursh-packaged"

    bash = formula_opt_bin("bash")/"bash"
    wrappers = {
      "scoursh"        => "scan.sh",
      "scoursh-vendor" => "tools/vendor-engines.sh",
    }
    wrappers["scoursh-sandbox"] = "tools/run-sandboxed.sh" if OS.mac?
    wrappers["scoursh-netns"] = "tools/run-in-netns.sh" if OS.linux?

    wrappers.each do |name, target|
      wrapper = libexec/"bin/#{name}"
      rm wrapper if wrapper.exist?
      wrapper.write <<~SH
        #!/bin/sh
        exec "#{bash}" "#{libexec}/#{target}" "$@"
      SH
      chmod 0755, wrapper
      bin.install_symlink wrapper
    end
  end

  def caveats
    <<~EOS
      scoursh keeps configuration, scan state, reports, and advisory data outside
      Homebrew, so upgrades do not remove them. Run `scoursh paths` to see where.

      SAST, IaC, DAST, and network scans work immediately. Dependency-CVE matching
      needs a locally built advisory database on a networked machine:
        scoursh-vendor advisories bulk --all --accept-unverified
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/scoursh --version")
    (testpath/"src/app.py").write "import os\nos.system(input())\n"
    scan_root = testpath/"scoursh"
    cp_r libexec/".", scan_root
    ENV["SCOURSH_HOME"] = testpath/"home"
    system formula_opt_bin("bash")/"bash", scan_root/"scan.sh", "sast",
           "--path", testpath/"src", "--out", testpath/"out", "--format", "json"
    assert_match "SAST-INJ-OS_COMMAND-01", (testpath/"out/findings.jsonl").read
  end
end
