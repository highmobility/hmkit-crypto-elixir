defmodule HmCrypto.MixProject do
  use Mix.Project

  def project do
    [
      app: :hm_crypto,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
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
      {:timex, "~> 3.4"},
      {:propcheck, "~> 1.1", only: :test},
      {:credo, "~> 0.8.10", only: [:dev, :test]},
      {:dialyxir, "~> 1.0.0-rc.3", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.18.1", only: :dev},
      {:earmark, "~> 1.2", only: :dev}
    ]
  end
end
