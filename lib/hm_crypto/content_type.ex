defmodule HmCrypto.ContentType do
  @type t :: :unknown | :auto_api | :vss

  def to_bin(content_type) do
    case content_type do
      :unknown -> 0x00
      :auto_api -> 0x01
      :vss -> 0x02
    end
  end

  def from_bin(content_type_bin) do
    case content_type_bin do
      0x00 -> :unknown
      0x01 -> :auto_api
      0x02 -> :vss
    end
  end
end
