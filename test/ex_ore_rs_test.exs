defmodule ExOreRsTest do
  use ExUnit.Case, async: false
  use ExUnitProperties
  doctest ExOreRs

  @prf_key :crypto.strong_rand_bytes(16)
  @prp_key :crypto.strong_rand_bytes(16)
  @seed :crypto.strong_rand_bytes(8)

  test "that plaintexts encrypted under different PRF keys are not comparable" do
    ct_a = ExOreRs.encrypt(1000, "abcdefghijklmnop", @prp_key, @seed)
    ct_b = ExOreRs.encrypt(1000, "1234567890abcdef", @prp_key, @seed)

    refute 0 == ExOreRs.compare(ct_a, ct_b)
  end

  test "that plaintexts encrypted under different PRP keys are not comparable" do
    ct_a = ExOreRs.encrypt(1000, @prf_key, "abcdefghijklmnop", @seed)
    ct_b = ExOreRs.encrypt(1000, @prf_key, "1234567890abcdef", @seed)

    refute 0 == ExOreRs.compare(ct_a, ct_b)
  end

  describe "PRF key" do
    test "that encryption errors when too short" do
      assert_raise ArgumentError, fn ->
        ExOreRs.encrypt(1, "short", @prp_key, @seed)
      end
    end

    test "that encryption errors when too long" do
      assert_raise ArgumentError, fn ->
        ExOreRs.encrypt(1, "this key is far too long", @prp_key, @seed)
      end
    end
  end

  describe "PRP key" do
    test "that encryption errors when too short" do
      assert_raise ArgumentError, fn ->
        ExOreRs.encrypt(1, @prf_key, "short", @seed)
      end
    end

    test "that encryption errors when too long" do
      assert_raise ArgumentError, fn ->
        ExOreRs.encrypt(1, @prf_key, "this key is also far too long", @seed)
      end
    end
  end

  describe "Arguments" do
    test "32-bit plaintext out of range returns an error" do
      pt = :math.pow(2, 32) |> trunc
      assert_raise ArgumentError, fn ->
        ExOreRs.encrypt(pt, @prf_key, @prp_key, @seed)
      end
    end

    test "64-bit plaintext out of range returns an error" do
      pt = :math.pow(2, 64) |> trunc
      assert_raise ArgumentError, fn ->
        ExOreRs.encrypt(pt, @prf_key, @prp_key, @seed, 64)
      end
    end

    test "n=65 raises argument error" do
      assert_raise ArgumentError, fn ->
        ExOreRs.encrypt(1, @prf_key, @prp_key, @seed, 65, 8)
      end
    end

    test "n=64, k=7 raises argument error" do
      assert_raise ArgumentError, fn ->
        ExOreRs.encrypt(1, @prf_key, @prp_key, @seed, 64, 7)
      end
    end
  end

  describe "n=32, k=8 (defaults)" do
    property "identical plaintexts will compare as equal" do
      check all pt <- plain_text(), max_runs: 1000 do
        ct = ExOreRs.encrypt(pt, @prf_key, @prp_key, @seed)
        assert 0 == ExOreRs.compare(ct, ct)
      end
    end

    property "correct order is revealed" do
      check all a <- plain_text(),
                b <- plain_text(),
                max_runs: 1000 do
        ct_a = ExOreRs.encrypt(a, @prf_key, @prp_key, @seed)
        ct_b = ExOreRs.encrypt(b, @prf_key, @prp_key, @seed)

        cond do
          a < b ->
            assert -1 == ExOreRs.compare(ct_a, ct_b)

          a > b ->
            assert 1 == ExOreRs.compare(ct_a, ct_b)

          a == b ->
            assert 0 == ExOreRs.compare(ct_a, ct_b)
        end
      end
    end

    property "all numbers smaller than the maximum should compare as less-than" do
      check all a <- integer(0..(max(32) - 1)), max_runs: 1000 do
        ct_a = ExOreRs.encrypt(a, @prf_key, @prp_key, @seed)
        ct_b = ExOreRs.encrypt(max(32), @prf_key, @prp_key, @seed)

        assert -1 == ExOreRs.compare(ct_a, ct_b)
      end
    end

    test "correct order is revealed given only one block different" do
      <<b::32>> = <<100, 75, 37, 11>>

      for <<a::32>> <- [<<100, 75, 37, 12>>, <<100, 75, 39, 11>>, <<100, 80, 37, 11>>, <<101, 75, 37, 11>>] do
        ct_a = ExOreRs.encrypt(a, @prf_key, @prp_key, @seed)
        ct_b = ExOreRs.encrypt(b, @prf_key, @prp_key, @seed)

        assert 1 == ExOreRs.compare(ct_a, ct_b)
      end
    end
  end

  describe "n=64, k=8" do
    setup do
      [n: 64, k: 8]
    end

    property "identical plaintexts will compare as equal", %{n: n, k: k} do
      check all pt <- plain_text(), max_runs: 1000 do
        ct = ExOreRs.encrypt(pt, @prf_key, @prp_key, @seed, n, k)
        assert 0 == ExOreRs.compare(ct, ct, n, k)
      end
    end

    property "correct order is revealed", %{n: n, k: k} do
      check all a <- plain_text(),
                b <- plain_text(),
                max_runs: 1000 do
        ct_a = ExOreRs.encrypt(a, @prf_key, @prp_key, @seed, n, k)
        ct_b = ExOreRs.encrypt(b, @prf_key, @prp_key, @seed, n, k)

        cond do
          a < b ->
            assert -1 == ExOreRs.compare(ct_a, ct_b, n, k)

          a > b ->
            assert 1 == ExOreRs.compare(ct_a, ct_b, n, k)

          a == b ->
            assert 0 == ExOreRs.compare(ct_a, ct_b, n, k)
        end
      end
    end

    property "all numbers smaller than the maximum should compare as less-than", %{n: n, k: k} do
      check all a <- integer(0..(max(n) - 1)), max_runs: 1000 do
        ct_a = ExOreRs.encrypt(a, @prf_key, @prp_key, @seed, n, k)
        ct_b = ExOreRs.encrypt(max(n), @prf_key, @prp_key, @seed, n, k)

        assert -1 == ExOreRs.compare(ct_a, ct_b, n, k)
      end
    end

    test "correct order is revealed given only one block different", %{n: n, k: k} do
      <<b::64>> = <<100, 75, 37, 11, 140, 19, 1, 220>>

      for <<a::64>> <- [
        <<101, 75, 37, 11, 140, 19, 1, 220>>,
        <<100, 79, 37, 11, 140, 19, 1, 220>>,
        <<100, 75, 38, 11, 140, 19, 1, 220>>,
        <<100, 75, 37, 20, 140, 19, 1, 220>>,
        <<100, 75, 37, 11, 150, 19, 1, 220>>,
        <<100, 75, 37, 11, 140, 20, 1, 220>>,
        <<100, 75, 37, 11, 140, 19, 2, 220>>,
        <<100, 75, 37, 11, 140, 19, 1, 223>>
      ] do

        ct_a = ExOreRs.encrypt(a, @prf_key, @prp_key, @seed, n, k)
        ct_b = ExOreRs.encrypt(b, @prf_key, @prp_key, @seed, n, k)

        assert 1 == ExOreRs.compare(ct_a, ct_b, n, k)
      end
    end
  end

  defp plain_text(n \\ 32) do
    integer(0..max(n))
  end

  defp max(n) do
    (:math.pow(2, n) |> trunc) - 1
  end
end
