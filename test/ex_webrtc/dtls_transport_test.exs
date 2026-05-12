defmodule ExWebRTC.DTLSTransportTest do
  use ExUnit.Case, async: true

  alias ExWebRTC.{DTLSTransport, Utils}

  {_pkey, cert} = ExDTLS.generate_key_cert()

  @fingerprint cert
               |> ExDTLS.get_cert_fingerprint()
               |> Utils.hex_dump()

  @rtp_header <<1::1, 0::1, 0::1, 0::1, 0::4, 0::1, 96::7, 1::16, 1::32, 1::32>>
  @next_rtp_header <<1::1, 0::1, 0::1, 0::1, 0::4, 0::1, 96::7, 2::16, 1::32, 1::32>>
  @rtp_payload <<0>>
  @rtp_packet <<@rtp_header::binary, @rtp_payload::binary>>
  @next_rtp_packet <<@next_rtp_header::binary, @rtp_payload::binary>>

  # empty rr packet
  @rtcp_rr_header <<2::2, 0::1, 0::5, 201::8, 1::16, 1::32>>
  @rtcp_rr_packet <<@rtcp_rr_header::binary>>

  defmodule MockICETransport do
    @behaviour ExWebRTC.ICETransport

    use GenServer

    @impl true
    def start_link(config), do: GenServer.start_link(__MODULE__, config)

    @impl true
    def on_data(ice_pid, dst_pid), do: GenServer.call(ice_pid, {:on_data, dst_pid})

    @impl true
    def send_data(ice_pid, data), do: GenServer.cast(ice_pid, {:send_data, data})

    @impl true
    def add_remote_candidate(ice_pid, _candidate), do: ice_pid

    @impl true
    def end_of_candidates(ice_pid), do: ice_pid

    @impl true
    def gather_candidates(ice_pid), do: ice_pid

    @impl true
    def get_role(ice_pid) do
      GenServer.call(ice_pid, :get_role)
    end

    @impl true
    def get_local_credentials(_state), do: {:ok, "testufrag", "testpwd"}

    @impl true
    def get_local_candidates(_ice_pid), do: []

    @impl true
    def get_remote_candidates(_ice_pid), do: []

    @impl true
    def restart(ice_pid), do: ice_pid

    @impl true
    def set_remote_credentials(ice_pid, _ufrag, _pwd), do: ice_pid

    @impl true
    def set_role(ice_pid, role) do
      GenServer.cast(ice_pid, {:set_role, role})
    end

    @impl true
    def get_stats(_ice_pid), do: %{}

    @impl true
    def close(ice_pid), do: GenServer.call(ice_pid, :close)

    @impl true
    def stop(ice_pid), do: GenServer.stop(ice_pid)

    def send_dtls(ice_pid, data), do: GenServer.cast(ice_pid, {:send_dtls, data})

    @impl true
    def init(tester: tester),
      do: {:ok, %{role: nil, on_data_dst: nil, tester: tester}}

    @impl true
    def handle_call({:on_data, dst_pid}, _from, state) do
      {:reply, :ok, %{state | on_data_dst: dst_pid}}
    end

    @impl true
    def handle_call(:get_role, _from, state) do
      {:reply, state.role, state}
    end

    @impl true
    def handle_call(:close, _from, state) do
      # TODO implement
      {:reply, :ok, state}
    end

    @impl true
    def handle_cast({:set_role, role}, state) do
      {:noreply, %{state | role: role}}
    end

    @impl true
    def handle_cast({:send_data, data}, state) do
      send(state.tester, {:mock_ice, data})
      {:noreply, state}
    end

    @impl true
    def handle_cast({:send_dtls, data}, state) do
      send(state.on_data_dst, {:ex_ice, self(), data})
      {:noreply, state}
    end
  end

  setup do
    {:ok, ice_pid} = MockICETransport.start_link(tester: self())

    assert {:ok, dtls} =
             DTLSTransport.start_link(ice_transport: MockICETransport, ice_pid: ice_pid)

    MockICETransport.on_data(ice_pid, dtls)
    assert_receive {:dtls_transport, ^dtls, {:state_change, :new}}

    %{dtls: dtls, ice_transport: MockICETransport, ice_pid: ice_pid}
  end

  test "cannot send data when handshake has not finished", %{dtls: dtls} do
    DTLSTransport.send_rtp(dtls, @rtp_packet)

    refute_receive {:mock_ice, _data}
  end

  test "buffers incoming data if DTLSTransport has not been started", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    :ok = DTLSTransport.set_ice_connected(dtls)

    remote_dtls = ExDTLS.init(mode: :client, dtls_srtp: true)
    {:ok, packets, _timeout} = ExDTLS.do_handshake(remote_dtls)

    Enum.each(packets, &ice_transport.send_dtls(ice_pid, {:data, &1}))
    refute_receive {:mock_ice, _packets}

    :ok = DTLSTransport.start_dtls(dtls, :passive, @fingerprint)

    assert_receive {:mock_ice, packets}
    assert is_binary(packets)
  end

  test "cannot start dtls more than once if it is not closed", %{dtls: dtls} do
    assert :ok = DTLSTransport.start_dtls(dtls, :passive, @fingerprint)
    assert {:error, :already_started} = DTLSTransport.start_dtls(dtls, :passive, @fingerprint)
  end

  test "can restart dtls if it is closed", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    remote_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)

    remote_fingerprint =
      remote_dtls
      |> ExDTLS.get_cert()
      |> ExDTLS.get_cert_fingerprint()
      |> Utils.hex_dump()

    :ok = DTLSTransport.start_dtls(dtls, :active, remote_fingerprint)
    :ok = DTLSTransport.set_ice_connected(dtls)

    # perform DTLS-SRTP handshake
    assert {:ok, _remote_lkm, _remote_rkm, _remote_profile} =
             check_handshake(dtls, ice_transport, ice_pid, remote_dtls)

    assert_receive {:dtls_transport, ^dtls, {:state_change, :connecting}}
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connected}}

    # close and send close_notify from remote to local
    assert {:ok, packets} = ExDTLS.close(remote_dtls)
    Enum.each(packets, &ice_transport.send_dtls(ice_pid, {:data, &1}))

    # assert local received close_notify and moved to the closed state
    assert_receive {:dtls_transport, ^dtls, {:state_change, :closed}}

    # start dtls transport again
    # flush old messages
    flush_mailbox(dtls)
    assert :ok = DTLSTransport.start_dtls(dtls, :active, @fingerprint)
    # assert dlts moved to the new state
    assert_receive {:dtls_transport, ^dtls, {:state_change, :new}}
  end

  test "initiates DTLS handshake when in active mode", %{dtls: dtls} do
    :ok = DTLSTransport.start_dtls(dtls, :active, @fingerprint)

    :ok = DTLSTransport.set_ice_connected(dtls)

    assert_receive {:mock_ice, packets}
    assert is_binary(packets)
  end

  test "won't initiate DTLS handshake when in passive mode", %{dtls: dtls} do
    :ok = DTLSTransport.start_dtls(dtls, :passive, @fingerprint)

    :ok = DTLSTransport.set_ice_connected(dtls)

    refute_receive({:mock_ice, _msg})
  end

  test "will retransmit after initiating handshake", %{dtls: dtls} do
    :ok = DTLSTransport.start_dtls(dtls, :active, @fingerprint)

    :ok = DTLSTransport.set_ice_connected(dtls)

    assert_receive {:mock_ice, _packets}

    assert_receive {:mock_ice, _retransmitted},
                   1000 + ExUnit.configuration()[:assert_receive_timeout]
  end

  test "will buffer packets and send when connected", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    :ok = DTLSTransport.start_dtls(dtls, :passive, @fingerprint)

    remote_dtls = ExDTLS.init(mode: :client, dtls_srtp: true)
    {:ok, packets, _timeout} = ExDTLS.do_handshake(remote_dtls)

    Enum.each(packets, &ice_transport.send_dtls(ice_pid, {:data, &1}))
    refute_receive {:mock_ice, _packets}

    :ok = DTLSTransport.set_ice_connected(dtls)
    assert_receive {:mock_ice, packets}
    assert is_binary(packets)
  end

  test "finishes handshake in active mode", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    remote_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)

    remote_fingerprint =
      remote_dtls
      |> ExDTLS.get_cert()
      |> ExDTLS.get_cert_fingerprint()
      |> Utils.hex_dump()

    :ok = DTLSTransport.start_dtls(dtls, :active, remote_fingerprint)
    :ok = DTLSTransport.set_ice_connected(dtls)

    assert {:ok, _, _, _} = check_handshake(dtls, ice_transport, ice_pid, remote_dtls)
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connecting}}
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connected}}

    # assert we can send data
    assert :ok = DTLSTransport.send_rtp(dtls, @rtp_packet)
    assert_receive {:mock_ice, <<@rtp_header::binary, _payload::binary>>}
    assert :ok = DTLSTransport.send_rtcp(dtls, @rtcp_rr_packet)
    assert_receive {:mock_ice, <<@rtcp_rr_header::binary, _payload::binary>>}
    assert :ok = DTLSTransport.send_data(dtls, <<1, 2, 3>>)
    assert_receive {:mock_ice, _datachannel_packet}
  end

  test "finishes handshake in passive mode", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    remote_dtls = ExDTLS.init(mode: :client, dtls_srtp: true)

    remote_fingerprint =
      remote_dtls
      |> ExDTLS.get_cert()
      |> ExDTLS.get_cert_fingerprint()
      |> Utils.hex_dump()

    :ok = DTLSTransport.start_dtls(dtls, :passive, remote_fingerprint)

    {:ok, packets, _timeout} = ExDTLS.do_handshake(remote_dtls)
    :ok = DTLSTransport.set_ice_connected(dtls)

    Enum.each(packets, &ice_transport.send_dtls(ice_pid, {:data, &1}))

    assert {:ok, _, _, _} = check_handshake(dtls, ice_transport, ice_pid, remote_dtls)
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connecting}}
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connected}}

    # assert we can send data
    assert :ok = DTLSTransport.send_rtp(dtls, @rtp_packet)
    assert_receive {:mock_ice, <<@rtp_header::binary, _payload::binary>>}
    assert :ok = DTLSTransport.send_rtcp(dtls, @rtcp_rr_packet)
    assert_receive {:mock_ice, <<@rtcp_rr_header::binary, _payload::binary>>}
    assert :ok = DTLSTransport.send_data(dtls, <<1, 2, 3>>)
    assert_receive {:mock_ice, _datachannel_packet}
  end

  test "drops packets when packet loss is set", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    remote_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)

    remote_fingerprint =
      remote_dtls
      |> ExDTLS.get_cert()
      |> ExDTLS.get_cert_fingerprint()
      |> Utils.hex_dump()

    :ok = DTLSTransport.start_dtls(dtls, :active, remote_fingerprint)
    :ok = DTLSTransport.set_ice_connected(dtls)

    assert {:ok, _, _, _} = check_handshake(dtls, ice_transport, ice_pid, remote_dtls)
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connecting}}
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connected}}

    # assert we can send data
    DTLSTransport.send_rtp(dtls, @rtp_packet)
    assert_receive {:mock_ice, <<@rtp_header::binary, _payload::binary>>}
    DTLSTransport.send_rtcp(dtls, @rtcp_rr_packet)
    assert_receive {:mock_ice, <<@rtcp_rr_packet::binary, _rest::binary>>}
    DTLSTransport.send_data(dtls, <<1, 2, 3>>)
    assert_receive {:mock_ice, _datachannel_packet}

    # now set packet-loss
    DTLSTransport.set_packet_loss(dtls, 100)
    DTLSTransport.send_rtp(dtls, @rtp_packet)
    refute_receive {:mock_ice, _rtp_packet}
    DTLSTransport.send_rtcp(dtls, @rtcp_rr_packet)
    refute_receive {:mock_ice, _rtcp_rr_packet}
    DTLSTransport.send_data(dtls, <<1, 2, 3>>)
    refute_receive {:mock_ice, _datachannel_packet}
  end

  test "closes on calling close/1", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    remote_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)

    remote_fingerprint =
      remote_dtls
      |> ExDTLS.get_cert()
      |> ExDTLS.get_cert_fingerprint()
      |> Utils.hex_dump()

    :ok = DTLSTransport.start_dtls(dtls, :active, remote_fingerprint)
    :ok = DTLSTransport.set_ice_connected(dtls)

    # perform DTLS-SRTP handshake
    assert {:ok, remote_lkm, remote_rkm, remote_profile} =
             check_handshake(dtls, ice_transport, ice_pid, remote_dtls)

    assert_receive {:dtls_transport, ^dtls, {:state_change, :connecting}}
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connected}}

    # create SRTP for remote side
    {_remote_in_srtp, remote_out_srtp} = setup_srtp(remote_lkm, remote_rkm, remote_profile)

    # assert packets can flow from local to remote
    :ok = DTLSTransport.send_rtp(dtls, @rtp_packet)
    assert_receive {:mock_ice, _rtp_packet}

    # close transport
    assert :ok = DTLSTransport.close(dtls)

    # flush close notify
    assert_receive {:mock_ice, _dtls_close_notify}

    # assert that data cannot be sent by local
    :ok = DTLSTransport.send_rtp(dtls, @rtp_packet)
    refute_receive {:mock_ice, _rtp_packet}
    :ok = DTLSTransport.send_rtcp(dtls, @rtcp_rr_packet)
    refute_receive {:mock_ice, _rtcp_packet}
    :ok = DTLSTransport.send_data(dtls, <<1, 2, 3>>)
    refute_receive {:mock_ice, _datachannel_packet}

    # assert that incoming data is ignored by local
    {:ok, protected} = ExLibSRTP.protect(remote_out_srtp, @rtp_packet)
    ice_transport.send_dtls(ice_pid, {:data, protected})
    refute_receive {:dtls_transport, ^dtls, {:rtp, _data}}

    # assert getting certs still works
    assert %{local_cert_info: local_cert, remote_cert_info: remote_cert} =
             DTLSTransport.get_certs_info(dtls)

    assert local_cert != nil
    assert remote_cert != nil
    assert DTLSTransport.get_fingerprint(dtls) != nil
  end

  test "closes on receiving close_notify DTLS alert", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    remote_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)

    remote_fingerprint =
      remote_dtls
      |> ExDTLS.get_cert()
      |> ExDTLS.get_cert_fingerprint()
      |> Utils.hex_dump()

    :ok = DTLSTransport.start_dtls(dtls, :active, remote_fingerprint)
    :ok = DTLSTransport.set_ice_connected(dtls)

    # perform DTLS-SRTP handshake
    assert {:ok, remote_lkm, remote_rkm, remote_profile} =
             check_handshake(dtls, ice_transport, ice_pid, remote_dtls)

    assert_receive {:dtls_transport, ^dtls, {:state_change, :connecting}}
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connected}}

    # create SRTP for remote side
    {_remote_in_srtp, remote_out_srtp} = setup_srtp(remote_lkm, remote_rkm, remote_profile)

    # assert packets can flow from remote to local
    {:ok, protected} = ExLibSRTP.protect(remote_out_srtp, @rtp_packet)
    ice_transport.send_dtls(ice_pid, {:data, protected})
    assert_receive {:dtls_transport, ^dtls, {:rtp, @rtp_packet}}

    # close and send close_notify from remote to local
    assert {:ok, packets} = ExDTLS.close(remote_dtls)
    Enum.each(packets, &ice_transport.send_dtls(ice_pid, {:data, &1}))

    # assert local received close_notify and moved to the closed state
    assert_receive {:dtls_transport, ^dtls, {:state_change, :closed}}

    # assert that data cannot be sent by local
    :ok = DTLSTransport.send_rtp(dtls, @rtp_packet)
    refute_receive {:mock_ice, _rtp_packet}
    :ok = DTLSTransport.send_rtcp(dtls, @rtcp_rr_packet)
    refute_receive {:mock_ice, _rtcp_packet}
    :ok = DTLSTransport.send_data(dtls, <<1, 2, 3>>)
    refute_receive {:mock_ice, _datachannel_packet}

    # assert that incoming data is ignored by local
    {:ok, protected} = ExLibSRTP.protect(remote_out_srtp, @next_rtp_packet)
    ice_transport.send_dtls(ice_pid, {:data, protected})
    refute_receive {:dtls_transport, ^dtls, {:rtp, _data}}

    # assert getting certs still works
    assert %{local_cert_info: local_cert, remote_cert_info: remote_cert} =
             DTLSTransport.get_certs_info(dtls)

    assert local_cert != nil
    assert remote_cert != nil
    assert DTLSTransport.get_fingerprint(dtls) != nil
  end

  defp check_handshake(dtls, ice_transport, ice_pid, remote_dtls) do
    assert_receive {:mock_ice, packets}

    case ExDTLS.handle_data(remote_dtls, packets) do
      :handshake_want_read ->
        check_handshake(dtls, ice_transport, ice_pid, remote_dtls)

      {:handshake_packets, packets, _timeout} ->
        Enum.each(packets, &ice_transport.send_dtls(ice_pid, {:data, &1}))
        check_handshake(dtls, ice_transport, ice_pid, remote_dtls)

      {:handshake_finished, lkm, rkm, profile, packets} ->
        Enum.each(packets, &ice_transport.send_dtls(ice_pid, {:data, &1}))
        {:ok, lkm, rkm, profile}

      {:handshake_finished, lkm, rkm, profile} ->
        {:ok, lkm, rkm, profile}
    end
  end

  test "emits :diagnostics and :failure_reason with :peer_fingerprint_mismatch before failing on bad fingerprint",
       %{
         dtls: dtls,
         ice_transport: ice_transport,
         ice_pid: ice_pid
       } do
    remote_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)

    # Pass the LOCAL cert fingerprint as if it were the remote's, so the
    # post-handshake fingerprint check fails.
    :ok = DTLSTransport.start_dtls(dtls, :active, @fingerprint)
    :ok = DTLSTransport.set_ice_connected(dtls)

    {:ok, _lkm, _rkm, _profile} = check_handshake(dtls, ice_transport, ice_pid, remote_dtls)

    assert_receive {:dtls_transport, ^dtls, {:state_change, :connecting}}

    assert_receive {:dtls_transport, ^dtls,
                    {:diagnostics, %{records_received: [_ | _] = _records}}}

    assert_receive {:dtls_transport, ^dtls, {:failure_reason, :peer_fingerprint_mismatch}}
    assert_receive {:dtls_transport, ^dtls, {:state_change, :failed}}
  end

  test "captures inbound DTLS records during handshake", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    remote_dtls = ExDTLS.init(mode: :client, dtls_srtp: true)
    {:ok, packets, _timeout} = ExDTLS.do_handshake(remote_dtls)

    :ok = DTLSTransport.start_dtls(dtls, :passive, @fingerprint)
    :ok = DTLSTransport.set_ice_connected(dtls)

    Enum.each(packets, &ice_transport.send_dtls(ice_pid, {:data, &1}))

    # Sync — wait until the GenServer has processed inbound packets.
    _ = :sys.get_state(dtls)

    state = :sys.get_state(dtls)
    assert is_list(state.records_received)
    assert length(state.records_received) > 0
    assert length(state.records_received) <= 16

    # Records were stored newest-first; the oldest should carry t_ms == 0.
    oldest = List.last(state.records_received)
    assert oldest.t_ms == 0
  end

  test "emits :diagnostics before :failure_reason on inbound DTLS error", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    :ok = DTLSTransport.start_dtls(dtls, :active, @fingerprint)
    :ok = DTLSTransport.set_ice_connected(dtls)

    # Drain the local ClientHello so the only outbound traffic that follows
    # the alert is what the failure path emits (or doesn't).
    assert_receive {:mock_ice, _client_hello}

    # Fatal handshake_failure alert from "remote" — OpenSSL aborts the
    # handshake, ExDTLS surfaces {:error, reason}, and the handler must
    # emit :diagnostics before :failure_reason and transition to :failed.
    alert = <<21, 254, 253, 0::16, 0::48, 2::16, 2, 40>>
    ice_transport.send_dtls(ice_pid, {:data, alert})

    assert_receive {:dtls_transport, ^dtls, {:diagnostics, %{records_received: records}}}

    assert [%{content_type: :alert, alert: %{level: :fatal, description: :handshake_failure}}] =
             records

    assert_receive {:dtls_transport, ^dtls, {:failure_reason, _reason}}
    assert_receive {:dtls_transport, ^dtls, {:state_change, :failed}}
  end

  test "drops trajectory buffer on :connected and does not emit :diagnostics", %{
    dtls: dtls,
    ice_transport: ice_transport,
    ice_pid: ice_pid
  } do
    remote_dtls = ExDTLS.init(mode: :server, dtls_srtp: true)

    remote_fingerprint =
      remote_dtls
      |> ExDTLS.get_cert()
      |> ExDTLS.get_cert_fingerprint()
      |> Utils.hex_dump()

    :ok = DTLSTransport.start_dtls(dtls, :active, remote_fingerprint)
    :ok = DTLSTransport.set_ice_connected(dtls)

    {:ok, _lkm, _rkm, _profile} = check_handshake(dtls, ice_transport, ice_pid, remote_dtls)

    assert_receive {:dtls_transport, ^dtls, {:state_change, :connecting}}
    assert_receive {:dtls_transport, ^dtls, {:state_change, :connected}}
    refute_receive {:dtls_transport, ^dtls, {:diagnostics, _}}

    state = :sys.get_state(dtls)
    assert state.records_received == []
    assert state.records_first_ms == nil
  end

  test "get_diagnostics/1 returns records_received in chronological order", %{dtls: dtls} do
    :ok = DTLSTransport.start_dtls(dtls, :passive, @fingerprint)

    # Cold: empty buffer.
    assert %{records_received: []} = DTLSTransport.get_diagnostics(dtls)

    # Inject three known entries. The buffer is prepended-newest-first inside
    # DTLSTransport state, so we set it in reverse-chronological order and
    # expect get_diagnostics/1 to reverse it back to chronological.
    record_a = %{t_ms: 0, content_type: :handshake}
    record_b = %{t_ms: 5, content_type: :handshake}
    record_c = %{t_ms: 12, content_type: :change_cipher_spec}

    :sys.replace_state(dtls, fn state ->
      %{state | records_received: [record_c, record_b, record_a]}
    end)

    assert %{records_received: [^record_a, ^record_b, ^record_c]} =
             DTLSTransport.get_diagnostics(dtls)
  end

  test "stop/1", %{dtls: dtls} do
    assert :ok == DTLSTransport.stop(dtls)
    assert false == Process.alive?(dtls)
  end

  defp setup_srtp(lkm, rkm, profile) do
    in_srtp = ExLibSRTP.new()
    out_srtp = ExLibSRTP.new()

    {:ok, crypto_profile} =
      ExLibSRTP.Policy.crypto_profile_from_dtls_srtp_protection_profile(profile)

    inbound_policy = %ExLibSRTP.Policy{
      ssrc: :any_inbound,
      key: rkm,
      rtp: crypto_profile,
      rtcp: crypto_profile
    }

    :ok = ExLibSRTP.add_stream(in_srtp, inbound_policy)

    outbound_policy = %ExLibSRTP.Policy{
      ssrc: :any_outbound,
      key: lkm,
      rtp: crypto_profile,
      rtcp: crypto_profile
    }

    :ok = ExLibSRTP.add_stream(out_srtp, outbound_policy)

    {in_srtp, out_srtp}
  end

  defp flush_mailbox(pid) do
    receive do
      {:dtls_transport, ^pid, _msg} -> flush_mailbox(pid)
    after
      0 -> :ok
    end
  end
end
