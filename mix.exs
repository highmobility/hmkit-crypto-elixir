defmodule HmCrypto.MixProject do
  use Mix.Project

  def project do
    [
      app: :hm_crypto,
      version: "2.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      preferred_cli_env: [
        "coveralls.json": :test
      ],
      test_coverage: [tool: ExCoveralls],
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :public_key]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:propcheck, "~> 1.4", only: :test},
      {:credo, "~> 1.5", only: [:dev, :test]},
      {:dialyxir, "~> 1.1", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.18.1", only: :dev},
      {:earmark, "~> 1.2", only: :dev},
      {:excoveralls, "~> 0.14.2", only: [:test], runtime: false}
    ]
  end
end
