defmodule BeamAudit.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/nshkrdotcom/beam_audit"
  @description "Reproducible BEAM source and dependency security audits with structural and semantic analysis and resumable AI-assisted review."

  def project do
    [
      app: :beam_audit,
      version: @version,
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "BeamAudit",
      description: @description,
      source_url: @source_url,
      homepage_url: @source_url,
      package: package(),
      docs: docs()
    ]
  end

  def application, do: [extra_applications: [:crypto, :logger]]

  defp deps do
    [
      {:ex_ast, "~> 0.12.10"},
      {:reach, "~> 2.8.4"},
      {:sobelow, "~> 0.19.0"},
      {:vulncheck, "~> 1.0.1"},
      {:agent_session_manager, "~> 0.17.6"},
      {:ex_doc, "~> 0.40.5", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib priv assets guides mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      logo: "assets/beam_audit.svg",
      assets: %{"assets" => "assets"},
      extras: [
        "README.md",
        "guides/getting-started.md",
        "guides/scope-and-safety.md",
        "guides/workflow.md",
        "guides/security-rules.md",
        "guides/dependencies.md",
        "guides/review-and-evidence.md",
        "guides/integration.md",
        "guides/results-and-recovery.md",
        "guides/validation.md",
        "CHANGELOG.md",
        "LICENSE"
      ],
      groups_for_extras: [
        "Getting started": ["README.md", "guides/getting-started.md"],
        "Audit workflow": [
          "guides/scope-and-safety.md",
          "guides/workflow.md",
          "guides/security-rules.md",
          "guides/dependencies.md",
          "guides/review-and-evidence.md"
        ],
        "Operations and integration": [
          "guides/integration.md",
          "guides/results-and-recovery.md",
          "guides/validation.md"
        ],
        Project: ["CHANGELOG.md", "LICENSE"]
      ],
      groups_for_modules: [
        "Public API": [BeamAudit],
        Execution: [BeamAudit.Run, BeamAudit.Scope],
        Analysis: [BeamAudit.Discovery, BeamAudit.Evidence, BeamAudit.Dependencies],
        Review: [BeamAudit.Review, BeamAudit.Report, BeamAudit.Findings]
      ]
    ]
  end
end
