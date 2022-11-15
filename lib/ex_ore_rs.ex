defmodule ExOreRs do
  use Rustler,
    otp_app: :ex_ore_rs

  # Size of the plaintext space in bits
  @default_n 32

  # ORE Block size
  @default_k 8

  def encrypt(plaintext, prf_key, prp_key) do
    encrypt(plaintext, prf_key, prp_key, @default_n, @default_k)
  end

  def encrypt(plaintext, prf_key, prp_key, n) do
    encrypt(plaintext, prf_key, prp_key, n, @default_k)
  end

  def encrypt(plaintext, prf_key, prp_key, n, k) do
    if k != 8 do
      raise ArgumentError, "only k=8 supported by ExOreRs.encrypt (got #{k})"
    end

    if byte_size(prf_key) != 16 do
      raise ArgumentError, "PRF key must be 16 octets (got #{byte_size(prf_key)}"
    end

    if byte_size(prp_key) != 16 do
      raise ArgumentError, "PRP key must be 16 octets (got #{byte_size(prp_key)}"
    end

    case n do
      32 ->
        encrypt_32_8(plaintext, prf_key, prp_key)
      64 ->
        encrypt_64_8(plaintext, prf_key, prp_key)
      _ ->
        raise ArgumentError, "only n={32,64} supported by ExOreRs.encrypt (got #{n})"
    end
  end

  def encrypt_32_8(_plaintext, _prf_key, _prp_key) do
    raise "NIF encrypt_32_8/4 not loaded"
  end

  def encrypt_64_8(_plaintext, _prf_key, _prp_key) do
    raise "NIF encrypt_64_8/4 not loaded"
  end

  @doc """
  Returns true if left <= right

  Handy for use with `Enum.sort`.
  """
  def compare_bool(left, right) do
    case ExOreRs.compare(left, right) do
      -1 -> true
      0 -> true
      _ -> false
    end
  end

  def compare(a, b) do
    compare(a, b, @default_n, @default_k)
  end

  def compare(a, b, n) do
    compare(a, b, n, @default_k)
  end

  def compare(a, b, n, k) do
    if k != 8 do
      raise ArgumentError, "only k=8 supported by ExOreRs.compare (got #{k})"
    end

    case n do
      32 ->
        compare_32_8(a, b)
      64 ->
        compare_64_8(a, b)
      _ ->
        raise ArgumentError, "only n={32,64} supported by ExOreRs.compare (got #{n})"
    end
  end

  def compare_32_8(_a, _b) do
    raise "NIF compare_32_8/2 not loaded"
  end

  def compare_64_8(_a, _b) do
    raise "NIF compare_64_8/2 not loaded"
  end
end
