defmodule ExStringUtil.Mixfile do
  use Mix.Project

  def project do
    [app: :ex_string_util,
     version: "0.1.0",
     elixir: "~> 1.4",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description(),
     package: package(),
     deps: deps()]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    # Specify extra applications you'll use from Erlang/Elixir
    [extra_applications: [:logger]]
  end

  defp description do
    """
    String Utility module. It helps perform some validation during application development
    particularly the ones that involve user input like REST API or Web Applications.
    """
  end

  defp package do
  [
   files: ["lib", "mix.exs", "README.md"],
   maintainers: ["Arsene Tochemey GANDOTE"],
   licenses: ["Apache 2.0"],
   links: %{"GitHub" => "https://github.com/Tochemey/ExString.git",
            "Docs" => "https://hexdocs.pm/ex_string_util"}
   ]
end

  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:ex_doc, "~> 0.11", only: :dev},
      {:earmark, "~> 0.1", only: :dev},
      {:dialyxir, "~> 0.3", only: [:dev]}
     ]
  end
end
