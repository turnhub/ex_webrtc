defmodule ExWebRTC.RTPReceiver.NACKResponderTest do
  use ExUnit.Case, async: true

  alias ExWebRTC.RTPSender.NACKResponder
  alias ExRTCP.Packet.TransportFeedback.NACK

  @responder %NACKResponder{}
  @media_ssrc 123_321
  @sender_ssrc 234_111
  @payload <<1, 2, 3, 4>>
  @packet ExRTP.Packet.new(@payload, ssrc: @media_ssrc)

  test "record_packet/2" do
    packet = %{@packet | sequence_number: 234}
    nack_responder = NACKResponder.record_packet(@responder, packet)
    assert nack_responder.packets == %{34 => packet}
  end

  test "get_rtx/2" do
    nack_responder =
      @responder
      |> NACKResponder.record_packet(%{@packet | sequence_number: 37})
      |> NACKResponder.record_packet(%{@packet | sequence_number: 38})
      |> NACKResponder.record_packet(%{@packet | sequence_number: 39})
      |> NACKResponder.record_packet(%{@packet | sequence_number: 40})

    nack = NACK.from_sequence_numbers(@media_ssrc, @sender_ssrc, [38, 39, 237])

    assert [
             %ExRTP.Packet{sequence_number: 38, payload: <<38::16, @payload::binary>>},
             %ExRTP.Packet{sequence_number: 39, payload: <<39::16, @payload::binary>>}
           ] = NACKResponder.get_rtx(nack_responder, nack)
  end
end
