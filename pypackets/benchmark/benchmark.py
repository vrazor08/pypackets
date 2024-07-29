from dataclasses import dataclass
from typing import Optional

from prettytable import PrettyTable

@dataclass(slots=True)
class Limitation:
  count  : Optional[int]   = None
  by_time: Optional[float] = None
  forever: Optional[bool]  = None 

def bench_test(bench_count: int, mul_step: float | int, pkts_size: int, func, **kwargc) -> str:
  by_time = 1
  rows = []
  for i in range(bench_count):
    limit = Limitation(by_time=int(by_time))
    pkts_count = func(limit=limit, **kwargc)
    pps = pkts_count // int(by_time)
    buffer_size = pkts_count * pkts_size * 8
    mbps = int(buffer_size / by_time / 1_000_000)
    rows.append([int(by_time), pkts_count, buffer_size//8//1024, pps, mbps])
    by_time *= mul_step
  table = PrettyTable(title=f"Sending bench for {pkts_size} bytes packet")
  table.field_names = ["Seconds", "Count", "Buf size(KB)", "pkts/s", "Mb/s"]
  table.add_rows(rows)
  return table.get_string()