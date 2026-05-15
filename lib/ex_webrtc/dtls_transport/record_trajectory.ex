defmodule ExWebRTC.DTLSTransport.RecordTrajectory do
  @moduledoc false

  # Pure DTLS record-layer parser (RFC 6347).
  #
  # Walks a UDP datagram and yields one map per record. Used by DTLSTransport
  # to capture a bounded trajectory of inbound records during the handshake;
  # the buffer is emitted on :failed so we can confirm or refute the
  # fragment-reordering hypothesis behind PROD-5532 dtls-stall events.

  @content_types %{
    20 => :change_cipher_spec,
    21 => :alert,
    22 => :handshake,
    23 => :application_data
  }

  @handshake_types %{
    0 => :hello_request,
    1 => :client_hello,
    2 => :server_hello,
    11 => :certificate,
    12 => :server_key_exchange,
    13 => :certificate_request,
    14 => :server_hello_done,
    15 => :certificate_verify,
    16 => :client_key_exchange,
    20 => :finished
  }

  @alert_levels %{1 => :warning, 2 => :fatal}

  @alert_descriptions %{
    0 => :close_notify,
    10 => :unexpected_message,
    20 => :bad_record_mac,
    21 => :decryption_failed,
    22 => :record_overflow,
    30 => :decompression_failure,
    40 => :handshake_failure,
    41 => :no_certificate,
    42 => :bad_certificate,
    43 => :unsupported_certificate,
    44 => :certificate_revoked,
    45 => :certificate_expired,
    46 => :certificate_unknown,
    47 => :illegal_parameter,
    48 => :unknown_ca,
    49 => :access_denied,
    50 => :decode_error,
    51 => :decrypt_error,
    60 => :export_restriction,
    70 => :protocol_version,
    71 => :insufficient_security,
    80 => :internal_error,
    86 => :inappropriate_fallback,
    90 => :user_canceled,
    100 => :no_renegotiation,
    110 => :unsupported_extension
  }

  @type record_entry :: map()

  @spec parse(binary(), now_ms :: integer(), first_ms :: integer() | nil) :: [record_entry()]
  def parse(data, now_ms, first_ms) do
    t_ms = if first_ms, do: now_ms - first_ms, else: 0
    walk(data, t_ms, [])
  end

  defp walk(<<>>, _t_ms, acc), do: Enum.reverse(acc)

  defp walk(
         <<ct, vmaj, vmin, epoch::16, seq_num::48, length::16, rest::binary>>,
         t_ms,
         acc
       ) do
    case rest do
      <<fragment::binary-size(length), more::binary>> ->
        record = parse_record(ct, vmaj, vmin, epoch, seq_num, length, fragment, t_ms)
        walk(more, t_ms, [record | acc])

      _ ->
        Enum.reverse([%{t_ms: t_ms, malformed: true, byte_size: 13 + byte_size(rest)} | acc])
    end
  end

  defp walk(short, t_ms, acc) do
    Enum.reverse([%{t_ms: t_ms, malformed: true, byte_size: byte_size(short)} | acc])
  end

  defp parse_record(ct, vmaj, vmin, epoch, seq_num, length, fragment, t_ms) do
    base = %{
      t_ms: t_ms,
      content_type: Map.get(@content_types, ct, {:unknown, ct}),
      version: {vmaj, vmin},
      epoch: epoch,
      seq_num: seq_num,
      length: length
    }

    case base.content_type do
      :handshake -> Map.put(base, :handshake, parse_handshake(fragment))
      :alert -> Map.put(base, :alert, parse_alert(fragment))
      _ -> base
    end
  end

  defp parse_handshake(
         <<type, msg_length::24, message_seq::16, fragment_offset::24, fragment_length::24,
           rest::binary>>
       ) do
    base = %{
      type: Map.get(@handshake_types, type, {:unknown, type}),
      msg_length: msg_length,
      message_seq: message_seq,
      fragment_offset: fragment_offset,
      fragment_length: fragment_length
    }

    # Only inspect the body when the record carries the complete message —
    # partial fragments cannot be safely interpreted as a typed structure.
    if fragment_offset == 0 and fragment_length == msg_length and
         byte_size(rest) >= fragment_length do
      parse_handshake_body(base, binary_part(rest, 0, fragment_length))
    else
      base
    end
  end

  defp parse_handshake(short), do: %{malformed: true, byte_size: byte_size(short)}

  # Extract fields that let downstream consumers cross-check identity of a
  # handshake message between flights (orphan vs. retransmit) without needing
  # raw record bytes. Only implemented for handshake types where it answers a
  # specific question; everything else passes through unchanged.

  defp parse_handshake_body(%{type: :server_hello} = base, body) do
    case body do
      <<_vmaj, _vmin, server_random::binary-size(32), sid_len, _sid::binary-size(sid_len),
        cipher_suite::16, _rest::binary>> ->
        base
        |> Map.put(:server_random, Base.encode16(server_random, case: :lower))
        |> Map.put(:cipher_suite, cipher_suite)

      _ ->
        base
    end
  end

  defp parse_handshake_body(%{type: :server_key_exchange} = base, body) do
    # ECDHE with curve_type = 3 (named_curve). Other curve types fall through
    # — the discriminator we care about (ECDH public point) is only meaningful
    # with named curves and the field set above us is fixed-shape.
    case body do
      <<3, named_curve::16, point_len, point::binary-size(point_len), _sig_hash, _sig_alg,
        sig_len::16, signature::binary-size(sig_len), _rest::binary>> ->
        base
        |> Map.put(:ecdh_named_curve, named_curve)
        |> Map.put(:ecdh_public, Base.encode16(point, case: :lower))
        |> Map.put(:signature, Base.encode16(signature, case: :lower))

      _ ->
        base
    end
  end

  defp parse_handshake_body(base, _body), do: base

  defp parse_alert(<<level, description, _rest::binary>>) do
    %{
      level: Map.get(@alert_levels, level, {:unknown, level}),
      description: Map.get(@alert_descriptions, description, {:unknown, description})
    }
  end

  defp parse_alert(short), do: %{malformed: true, byte_size: byte_size(short)}
end
