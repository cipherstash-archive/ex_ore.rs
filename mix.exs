defmodule ExOreRs.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_ore_rs,
      version: "0.2.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      description: "Wrapper for the Rust-based ORE cryptographic library ore.rs",
      deps: deps(),
      package: package(),
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [extra_applications: [:logger]]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.23", only: :dev, runtime: false},
      {:stream_data, "~> 0.5.0", only: :test},
      {:rustler, "~> 0.23.0"},
    ]
  end

  defp package do
    [
      files: ["lib", "mix.exs", "native", "README.md", "priv"],
      maintainers: ["Matt Palmer"],
      licenses: ["Apache 2.0"],
      links: %{"GitHub" => "https://github.com/cipherstash/ex_ore.rs"}
    ]
  end
end
