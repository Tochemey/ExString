defmodule ExStringUtil do
  @moduledoc """
  This module helps validate any string from user input.
  """

  @doc ~S"""
  This function checks whether a given string is alphanumeric.
  It will return true when the string is valid or false on the contrary.

  ## Parameters

    - string0: String to validate

  ## Returns

    - true when the `string0` is alphanumeric
    - false when the `string0` is not a valid alphanumeric

  ## Examples

      iex>ExStringUtil.is_alphanumeric("Password12")
      true
      iex>ExStringUtil.is_alphanumeric("[]")
      false

  """
  @spec is_alphanumeric(String.t) :: boolean
  def is_alphanumeric(string0) when  is_binary(string0) do
    Regex.match?(~r/^[\p{Ll}\p{Lm}\p{Lo}\p{Lt}\p{Lu}\p{Nd}]+$/, string0)
  end

  @doc ~S"""
  This function checks whether a given string `string0` is a valid email.
  It will return true when the string is a valid email or false on the contrary.
  The validation is not done against the domain name.

  ## Parameters

    - string0: String to validate

  ## Returns

      - true when the `string0` is valid email
      - false when the `string0` is not a valid email.

      ## Examples

          iex>ExStringUtil.is_email("elixir@erlang.com")
          true
          iex>ExStringUtil.is_email("elixir")
          false

  """
  @spec is_email(String.t) :: boolean
  def is_email(string0) when is_binary(string0) do
    Regex.match?(~r/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$/, string0)
  end

  @doc ~S"""
  This function checks whether a given string `string0` contains only alphabets.
  It will return true when the string contains only alphabets or false on the contrary.

  ## Parameters

    - string0: String to validate

  ## Returns

      - true when the `string0` contains only alphabets
      - false when the `string0` does not contains only alphabets.

  ## Examples

      iex>ExStringUtil.is_alpha("Password12")
      false
      iex>ExStringUtil.is_alphanumeric("Password")
      true

  """
  @spec is_alpha(String.t) :: boolean
  def is_alpha(string0) when is_binary(string0) do
    Regex.match?(~r/^[a-zA-Z]$/, string0)
  end

  @doc ~S"""
  This function checks whether a given `string0` is empty or not.

    ## Parameters

      - string0: String to validate

    ## Returns

        - true when the `string0` is empty
        - false when the `string0` is not empty

    ## Examples

        iex>ExStringUtil.is_empty("Password12")
        false
        iex>ExStringUtil.is_empty("")
        true
  """
  @spec is_empty(String.t) :: boolean
  def is_empty(string0) when is_binary(string0) do
      String.length(string0) == 0
  end

  @doc ~S"""
  This function helps check whether the string `string0` is a valid url.

  ## Parameters

    - string0: String to validate

  ## Returns

      - true when the `string0` is valid url
      - false when the `string0` is not a valid url

  ## Examples

      iex>ExStringUtil.is_url("Password12")
      false
      iex>ExStringUtil.is_url("https://www.google.com")
      true
      iex>ExStringUtil.is_url("www.swift-rider.com")
      true

  """
  @spec is_url(String.t) :: boolean
  def is_url(string0) when is_binary(string0) do
    regex =
       ~r"^(?:(?:(ht|f)tps?|file|news|gopher):\/\/)?(([\w!~*'().&=+$%-]+:)?[\w!~*'().&=+$%-]+@)?(([0-9]{1,3}.){3}[0-9]{1,3}|([\w!~*'()-]+.)*([\w^-][\w-]{0,61})?[\w].[a-z]{2,6})(:[0-9]{1,4})?((/*)|(/+[\w!~*'().;?:@&=+$,%#-]+)+/*)$"

    Regex.match?(regex, string0)
  end

  @doc ~S"""
  This function helps check whether the string `string0` is in valid money format.
  The validation is done based upon the currency position in the string.

  ## Parameters

    - string0: String to validate
    - right: boolean the currency symbol position in the string `string0`

  ## Returns

      - true when the `string0` is valid url
      - false when the `string0` is not a valid url
  """
  @spec is_money(String.t, boolean) :: boolean
  def is_money(string0, right \\ true) when is_binary(string0) do
    regex = cond do
      is_empty(string0) == true ->
        false
      true ->
        if right do
          ~r/^(?!0,?\d)(?:\d{1,3}(?:([,\.])\d{3})?(?:\1\d{3})*|(?:\d+))((?!\1)[,\.]\d{2})?(?<!\x{00a2})\p{Sc}?$/
        else
          ~r/^(?!\x{00a2})\p{Sc}?(?!0,?\d)(?:\d{1,3}(?:([,\.])\d{3})?(?:\1\d{3})*|(?:\d+))((?!\1)[,\.]\d{2})?$/
        end
    end
    Regex.match?(regex, string0)
  end

  @doc ~S"""
  This function helps check whether the string `string0` is in valid time format.
  Validates times as 12hr or 24hr (HH:MM) or am/pm ([H]H:MM[a|p]m).
  Matches times separated by either : or . will match a 24 hour time, or a 12 hour time with AM or PM specified.
  Allows 0-59 minutes, and 0-59 seconds. Seconds are not required.

  ## Parameters
    - string0: String to validate

  ## Returns

      - true when the `string0` is valid time
      - false when the `string0` is not a valid time

  ## Examples

        iex>ExStringUtil.is_time("12:23pm")
        true
        iex>ExStringUtil.is_time("01:34am")
        true
  """
  @spec is_time(String.t) :: boolean
  def is_time(string0) when is_binary(string0) do
    regex = ~r/^((([0]?[1-9]|1[0-2])(:|\.)[0-5][0-9]((:|\.)[0-5][0-9])?( )?(AM|am|aM|Am|PM|pm|pM|Pm))|(([0]?[0-9]|1[0-9]|2[0-3])(:|\.)[0-5][0-9]((:|\.)[0-5][0-9])?))$/
    Regex.match?(regex, string0)
  end

  @doc ~S"""

  Time validation, determines if the string passed is a valid time.
  Validates time as 24hr (HH:MM) or am/pm ([H]H:MM[a|p]m)
  Does not allow/validate seconds.

  ## Parameters

    - string0: String to validate
  ## Returns

      - true when the `string0` is valid time as 24
      - false when the `string0` is not a time as 24

  ## Examples

      iex>ExStringUtil.is_time_24("13:00")
      true
      iex>ExStringUtil.is_time_24("1:23 PM")
      true
  """
  @spec is_time_24(String.t) :: boolean
  def is_time_24(string0) when is_binary(string0) do
    regex = ~r/^((0?[1-9]|1[012])(:[0-5]\d){0,2} ?([AP]M|[ap]m))$|^([01]\d|2[0-3])(:[0-5]\d){0,2}$/
    Regex.match?(regex, string0)
  end

  @doc ~S"""
  Checks whether a given string `string0` is a numeric value.
  It returns true when the string is numeric string and false on the contrary.

  ## Parameters

    - string0: String to validate

  ## Returns

      - true when the `string0` is a number
      - false when the `string0` is not a number

  ## Examples

      iex>ExStringUtil.is_numeric("123")
      true
      iex>ExStringUtil.is_numeric("A2")
      false
  """
  @spec is_numeric(String.t) :: boolean
  def is_numeric(string0) when is_binary(string0) do
    regex = ~r/^([-+]?[0-9]+)$/
    Regex.match?(regex, string0)
  end

  @doc ~S"""
  Checks whether the string `string0` is a valid boolean.

  ## Parameters

    - string0: String to validate

  ## Returns

      - true when the `string0` is a number
      - false when the `string0` is not a number

  ## Examples

      iex>ExStringUtil.is_boolean("1")
      true
      iex>ExStringUtil.is_boolean("0")
      true
  """
  @spec is_boolean(String.t) :: boolean
  def is_boolean(string0) when is_binary(string0) do
    if is_empty(string0) do
      false
    else
      cond do
        is_numeric(string0) == true ->
          {parsed, ""} = Integer.parse(string0)
          parsed == 1 ||parsed == 0
        string0 == "true" || string0 == "false" -> true
        string0 == "1" || string0 == "0" -> true
        true -> false
      end
    end
  end

  @doc ~S"""
  Checks if a value is a natural number.

  ## Parameters

    - string0: String to validate

  ## Returns

      - true when the `string0` is a natural number
      - false when the `string0` is not a natural number

  ## Examples

      iex>ExStringUtil.is_natural_number("123")
      true
      iex>ExStringUtil.is_natural_number("023", true)
      false

  """
  @spec is_natural_number(String.t, boolean) :: boolean
  def is_natural_number(string0, allow_zero \\ false) when is_binary(string0) do
     regex =
       if allow_zero do
         ~r/^(?:0|[1-9][0-9]*)$/
       else
         ~r/^[1-9][0-9]*$/
       end

    Regex.match?(regex, string0)
  end

  @doc ~S"""
  Checks that a value is a valid UUID - http://tools.ietf.org/html/rfc4122

  ## Parameters

    - string0: String to validate

  ## Returns

      - true when the `string0` is a UUID
      - false when the `string0` is not a UUID

  ## Examples

      iex>ExStringUtil.is_uuid("3F2504E0-4F89-11D3-9A0C-0305E82C3301")
      true
  """
  @spec is_uuid(String.t) :: boolean
  def is_uuid(string0) when is_binary(string0) do
    Regex.match?(~r/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[0-5][a-fA-F0-9]{3}-[089aAbB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$/, string0)
  end

  @doc ~S"""
  Returns true if field is left blank -OR- only whitespace characters are present in its value
  Whitespace characters include Space, Tab, Carriage Return, Newline

  ## Parameters

    - string0: String to validate

  ## Returns

      - true when the `string0` is blank
      - false when the `string0` is not blank

  ## Examples

      iex>ExStringUtil.is_blank("\t")
      true
  """
  def is_blank(string0) when is_binary(string0) do
    Regex.match?(~r/[^\\s]/, string0)
  end

  @doc ~S"""
  Date validation, determines if the string passed is a valid date.
  keys that expect full month, day and year will validate leap years.

  Years are valid from 1800 to 2999.

  ## Parameters

    - string0: String to validate
    - format: date format to use. The following formats are allowed:
           - `dmy` 27-12-2006 or 27-12-06 separators can be a space, period, dash, forward slash
           - `mdy` 12-27-2006 or 12-27-06 separators can be a space, period, dash, forward slash
           - `ymd` 2006-12-27 or 06-12-27 separators can be a space, period, dash, forward slash
           - `dMy` 27 December 2006 or 27 Dec 2006
           -`Mdy` December 27, 2006 or Dec 27, 2006 comma is optional
           - `My` December 2006 or Dec 2006
           - `my` 12/2006 or 12/06 separators can be a space, period, dash, forward slash
           - `ym` 2006/12 or 06/12 separators can be a space, period, dash, forward slash
           - `y` 2006 just the year without any separators


  ## Returns

      - true when the `string0` is blank
      - false when the `string0` is not blank

  ## Examples

      iex>ExStringUtil.is_date!("2006-12-27")
      true
  """
  @spec is_date!(String.t, String.t) :: boolean | ArgumentError.t
  def is_date!(string0, format \\ "ymd") when is_binary(string0) do
    month = "(0[123456789]|10|11|12)"
    separator = "([- /.])"
    four_digit_year = "(([1][8-9][0-9][0-9])|([2][0-9][0-9][0-9]))"
    two_digit_year = "([0-9]{2})"
    year = "(?:" <> four_digit_year <> "|" <> two_digit_year <> ")"

    regex = cond do
              format == "dmy" ->
                "^(?:(?:31(\\/|-|\\.|\\x20)(?:0?[13578]|1[02]))\\1|(?:(?:29|30)" <>
                separator <> "(?:0?[1,3-9]|1[0-2])\\2))(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$|^(?:29" <>
                separator <>
                 "0?2\\3(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\\d|2[0-8])" <>
                separator <> "(?:(?:0?[1-9])|(?:1[0-2]))\\4(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$"
              format == "mdy" ->
                "^(?:(?:(?:0?[13578]|1[02])(\\/|-|\\.|\\x20)31)\\1|(?:(?:0?[13-9]|1[0-2])" <>
                separator <> "(?:29|30)\\2))(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$|^(?:0?2" <>
                separator <> "'29\\3(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:(?:0?[1-9])|(?:1[0-2]))" <>
                separator <> "(?:0?[1-9]|1\\d|2[0-8])\\4(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$"
              format == "ymd" ->
                "^(?:(?:(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))" <> separator <> "(?:0?2\\1(?:29)))|(?:(?:(?:1[6-9]|[2-9]\\d)?\\d{2})" <> separator <> "(?:(?:(?:0?[13578]|1[02])\\2(?:31))|(?:(?:0?[1,3-9]|1[0-2])\\2(29|30))|(?:(?:0?[1-9])|(?:1[0-2]))\\2(?:0?[1-9]|1\\d|2[0-8]))))$"
              format == "dMy" ->
                "^((31(?!\\ (Feb(ruary)?|Apr(il)?|June?|(Sep(?=\\b|t)t?|Nov)(ember)?)))|((30|29)(?!\\ Feb(ruary)?))|(29(?=\\ Feb(ruary)?\\ (((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(0?[1-9])|1\\d|2[0-8])\\ (Jan(uary)?|Feb(ruary)?|Ma(r(ch)?|y)|Apr(il)?|Ju((ly?)|(ne?))|Aug(ust)?|Oct(ober)?|(Sep(?=\\b|t)t?|Nov|Dec)(ember)?)\\ ((1[6-9]|[2-9]\\d)\\d{2})$"
              format == "Mdy" ->
                "^(?:(((Jan(uary)?|Ma(r(ch)?|y)|Jul(y)?|Aug(ust)?|Oct(ober)?|Dec(ember)?)\\ 31)|((Jan(uary)?|Ma(r(ch)?|y)|Apr(il)?|Ju((ly?)|(ne?))|Aug(ust)?|Oct(ober)?|(Sep)(tember)?|(Nov|Dec)(ember)?)\\ (0?[1-9]|([12]\\d)|30))|(Feb(ruary)?\\ (0?[1-9]|1\\d|2[0-8]|(29(?=,?\\ ((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))))\\,?\\ ((1[6-9]|[2-9]\\d)\\d{2}))$"
              format == "My" ->
                "^(Jan(uary)?|Feb(ruary)?|Ma(r(ch)?|y)|Apr(il)?|Ju((ly?)|(ne?))|Aug(ust)?|Oct(ober)?|(Sep(?=\\b|t)t?|Nov|Dec)(ember)?)" <> separator <> "((1[6-9]|[2-9]\\d)\\d{2})$"
              format == "my" ->
                "^(" <> month <> separator <> year <> ")$"
              format == "ym" ->
                "^(" <> year <> separator <> month <> ")$"
              format == "y" ->
                "^(" <> four_digit_year <> ")$"
              true ->
                "^(?:(?:(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))" <> separator <> "(?:0?2\\1(?:29)))|(?:(?:(?:1[6-9]|[2-9]\\d)?\\d{2})" <> separator <> "(?:(?:(?:0?[13578]|1[02])\\2(?:31))|(?:(?:0?[1,3-9]|1[0-2])\\2(29|30))|(?:(?:0?[1-9])|(?:1[0-2]))\\2(?:0?[1-9]|1\\d|2[0-8]))))$"
    end
    case Regex.compile(regex) do
      {:ok, reg} ->
        Regex.match?(reg, string0)
      {:error, reason} -> raise ArgumentError, message: reason
    end
  end

  @doc ~S"""
  Validation of an IP address.


  ## Parameters

    - string0: String to validate
    - version: the version of IP to check for. The following values are accepted
            - v4 for IP v4
            - v6 for IP v6

  ## Returns

      - true when the `string0` is an ip
      - false when the `string0` is not an ip

  ## Examples

      iex>ExStringUtil.is_ip!("192.168.254.46")
      true
  """
  @spec is_ip!(String.t, String.t) :: boolean | ArgumentError.t
  def is_ip!(string0, version \\ "v4") when is_binary(string0) do
    reg_v4 = "(?:(?:25[0-5]|2[0-4][0-9]|(?:(?:1[0-9])?|[1-9]?)[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|(?:(?:1[0-9])?|[1-9]?)[0-9])"
    reg_v6 = "((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}"
            <>
            "(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})"
            <>
            "|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})"
            <>
            "(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)"
            <>
            "{4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2}))"
            <>
            "{3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}"
            <>
            "((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|"
            <>
            "((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}"
            <>
            "((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2}))"
            <>
            "{3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4})"
            <>
            "{0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)"
            <>
            "|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]"
            <>
            "\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4})"
            <>
            "{1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?"

    case version do
       "v4" ->
         case Regex.compile(reg_v4) do
           {:ok, regex} -> Regex.match?(regex, string0)
           {:error, reason} -> raise(reason)
         end
       "v6" ->
         case Regex.compile(reg_v6) do
           {:ok, regex} -> Regex.match?(regex, string0)
           {:error, reason} -> raise(reason)
         end
       _ ->  raise ArgumentError, message: "no ip version specified"
    end

  end
end
