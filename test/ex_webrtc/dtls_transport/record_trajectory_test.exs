defmodule ExWebRTC.DTLSTransport.RecordTrajectoryTest do
  use ExUnit.Case, async: true

  alias ExWebRTC.DTLSTransport.RecordTrajectory

  # Helpers — build DTLS record + handshake bytes from named fields.
  # Record layout (RFC 6347 §4.1): ContentType(1) + Version(2) + Epoch(2) +
  # SeqNum(6) + Length(2) + Fragment(Length).
  defp record(content_type, length, body, opts \\ []) do
    epoch = Keyword.get(opts, :epoch, 0)
    seq = Keyword.get(opts, :seq, 0)
    {vmaj, vmin} = Keyword.get(opts, :version, {254, 253})

    <<content_type, vmaj, vmin, epoch::16, seq::48, length::16, body::binary>>
  end

  # Handshake header (RFC 6347 §4.2.2): Type(1) + Length(3) + MessageSeq(2) +
  # FragmentOffset(3) + FragmentLength(3) + Body(FragmentLength).
  defp handshake(type, opts \\ []) do
    msg_length = Keyword.get(opts, :msg_length, 37)
    message_seq = Keyword.get(opts, :message_seq, 0)
    fragment_offset = Keyword.get(opts, :fragment_offset, 0)
    fragment_length = Keyword.get(opts, :fragment_length, msg_length)
    body = :binary.copy(<<0>>, fragment_length)

    {<<type, msg_length::24, message_seq::16, fragment_offset::24, fragment_length::24,
       body::binary>>, fragment_length}
  end

  describe "parse/3 — record header only" do
    test "parses ChangeCipherSpec record" do
      bytes = record(20, 1, <<1>>, seq: 5)

      assert [
               %{
                 t_ms: 0,
                 content_type: :change_cipher_spec,
                 version: {254, 253},
                 epoch: 0,
                 seq_num: 5,
                 length: 1
               }
             ] = RecordTrajectory.parse(bytes, 100, nil)
    end

    test "parses ApplicationData record" do
      bytes = record(23, 4, <<1, 2, 3, 4>>, epoch: 1, seq: 42)

      assert [%{content_type: :application_data, epoch: 1, seq_num: 42, length: 4}] =
               RecordTrajectory.parse(bytes, 100, nil)
    end

    test "computes t_ms from first_ms anchor" do
      bytes = record(20, 1, <<1>>)

      assert [%{t_ms: 0}] = RecordTrajectory.parse(bytes, 100, nil)
      assert [%{t_ms: 25}] = RecordTrajectory.parse(bytes, 125, 100)
    end
  end

  describe "parse/3 — handshake records" do
    test "parses ClientHello" do
      {hs_body, hs_len} = handshake(1, msg_length: 37)
      bytes = record(22, hs_len + 12, hs_body)

      assert [
               %{
                 content_type: :handshake,
                 handshake: %{
                   type: :client_hello,
                   msg_length: 37,
                   message_seq: 0,
                   fragment_offset: 0,
                   fragment_length: 37
                 }
               }
             ] = RecordTrajectory.parse(bytes, 100, nil)
    end

    test "parses fragmented Certificate (3 fragments, out-of-order)" do
      # 1500-byte Certificate split into 3 × 500-byte fragments, arriving
      # in the order: middle, end, start (simulates relay-path reordering).
      {f_mid, _} = handshake(11, msg_length: 1500, fragment_offset: 500, fragment_length: 500)
      {f_end, _} = handshake(11, msg_length: 1500, fragment_offset: 1000, fragment_length: 500)
      {f_start, _} = handshake(11, msg_length: 1500, fragment_offset: 0, fragment_length: 500)

      bytes_mid = record(22, 512, f_mid, seq: 0)
      bytes_end = record(22, 512, f_end, seq: 1)
      bytes_start = record(22, 512, f_start, seq: 2)

      [m, e, s] =
        Enum.flat_map([bytes_mid, bytes_end, bytes_start], &RecordTrajectory.parse(&1, 100, nil))

      assert m.handshake.fragment_offset == 500
      assert e.handshake.fragment_offset == 1000
      assert s.handshake.fragment_offset == 0
      assert m.seq_num == 0
      assert e.seq_num == 1
      assert s.seq_num == 2
    end

    test "degrades unknown handshake type to {:unknown, n}" do
      {hs_body, hs_len} = handshake(99, msg_length: 5)
      bytes = record(22, hs_len + 12, hs_body)

      assert [%{handshake: %{type: {:unknown, 99}}}] = RecordTrajectory.parse(bytes, 100, nil)
    end
  end

  describe "parse/3 — alert records" do
    test "parses fatal handshake_failure alert" do
      bytes = record(21, 2, <<2, 40>>)

      assert [%{content_type: :alert, alert: %{level: :fatal, description: :handshake_failure}}] =
               RecordTrajectory.parse(bytes, 100, nil)
    end

    test "parses warning close_notify alert" do
      bytes = record(21, 2, <<1, 0>>)

      assert [%{alert: %{level: :warning, description: :close_notify}}] =
               RecordTrajectory.parse(bytes, 100, nil)
    end

    test "degrades unknown alert codes to {:unknown, n}" do
      bytes = record(21, 2, <<7, 200>>)

      assert [%{alert: %{level: {:unknown, 7}, description: {:unknown, 200}}}] =
               RecordTrajectory.parse(bytes, 100, nil)
    end
  end

  describe "parse/3 — multiple records per datagram" do
    test "yields one entry per record, sharing t_ms" do
      bytes = record(20, 1, <<1>>, seq: 0) <> record(22, 49, elem(handshake(1), 0), seq: 1)

      assert [
               %{content_type: :change_cipher_spec, seq_num: 0, t_ms: 5},
               %{content_type: :handshake, seq_num: 1, t_ms: 5}
             ] = RecordTrajectory.parse(bytes, 105, 100)
    end
  end

  describe "parse/3 — malformed input" do
    test "marks truncated record (declared length exceeds remaining bytes)" do
      # Record header declares length=100 but only 5 body bytes follow.
      bytes = <<22, 254, 253, 0::16, 0::48, 100::16, 0, 0, 0, 0, 0>>

      assert [%{malformed: true, byte_size: 18}] = RecordTrajectory.parse(bytes, 100, nil)
    end

    test "marks input shorter than 13-byte record header" do
      bytes = <<22, 254, 253>>

      assert [%{malformed: true, byte_size: 3}] = RecordTrajectory.parse(bytes, 100, nil)
    end

    test "appends malformed sentinel after well-formed records" do
      good = record(20, 1, <<1>>, seq: 0)
      bad = <<22, 254, 253>>

      assert [%{content_type: :change_cipher_spec}, %{malformed: true}] =
               RecordTrajectory.parse(good <> bad, 100, nil)
    end

    test "marks handshake record with fragment shorter than 12-byte header" do
      bytes = record(22, 5, <<1, 2, 3, 4, 5>>)

      assert [
               %{
                 content_type: :handshake,
                 length: 5,
                 handshake: %{malformed: true, byte_size: 5}
               }
             ] = RecordTrajectory.parse(bytes, 100, nil)
    end

    test "marks alert record with fragment shorter than 2-byte header" do
      bytes = record(21, 1, <<2>>)

      assert [
               %{
                 content_type: :alert,
                 length: 1,
                 alert: %{malformed: true, byte_size: 1}
               }
             ] = RecordTrajectory.parse(bytes, 100, nil)
    end
  end
end
