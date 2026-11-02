defmodule ExWebRTC.RTPSender.NACKResponder do
  @moduledoc false

  alias ExRTP.Packet
  alias ExRTCP.Packet.TransportFeedback.NACK

  @max_packets 200

  @type t() :: %__MODULE__{
          packets: %{non_neg_integer() => Packet.t()}
        }

  defstruct packets: %{}

  @spec record_packet(t(), Packet.t()) :: t()
  def record_packet(responder, packet) do
    key = rem(packet.sequence_number, @max_packets)
    packets = Map.put(responder.packets, key, packet)

    %__MODULE__{responder | packets: packets}
  end

  @spec get_rtx(t(), NACK.t()) :: [ExRTP.Packet.t()]
  def get_rtx(responder, nack) do
    nack
    |> NACK.to_sequence_numbers()
    |> Enum.map(fn seq_no -> {seq_no, Map.get(responder.packets, rem(seq_no, @max_packets))} end)
    |> Enum.filter(fn {seq_no, packet} -> packet != nil and packet.sequence_number == seq_no end)
    |> Enum.map(fn {seq_no, packet} ->
      %Packet{packet | payload: <<seq_no::16, packet.payload::binary>>}
    end)
  end
end
