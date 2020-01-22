# HmCrypto
# Copyright (C) 2018 High-Mobility GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see http://www.gnu.org/licenses/.
#
# Please inquire about commercial licensing options at
# licensing@high-mobility.com

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
