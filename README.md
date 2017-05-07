# ExStringUtil
========================================

**Overview**
String Utility module. It helps perform some validation during application development
particularly the ones that involve user input like REST API or Web Applications.

## **License**
[Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0.txt)

## **Features**
The module at its current version features the following functions:
* is_alpha/1
* is_alphanumeric/1
* is_blank/1
* is_boolean/1
* is_date!/2
* is_email/1
* is_empty/1
* is_ip!/2
* is_money/2
* is_natural_number/2
* is_numeric/1
* is_time/1
* is_time_24/1
* is_url/1
* is_uuid/1

## Installation

The package can be installed
by adding `ex_string_util` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:ex_string_util, "~> 0.1.0"}]
end
```

The docs can be found at [https://hexdocs.pm/ex_string_util](https://hexdocs.pm/ex_string_util).
