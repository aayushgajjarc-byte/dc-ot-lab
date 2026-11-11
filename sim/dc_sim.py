#!/usr/bin/env python3
"""
L0 process simulator: Data Centre with 3 rooms (Admin, Reception, Server).

Time scale : 1 real second = 1 simulated minute  (24 min = 1 simulated day)
Outside T  : 00-06 20C | 06-12 ramp 20->35C | 12-18 35C | 18-24 ramp 35->20C
Load       : 09-18 full (office hours), otherwise minimal
Thermal    : per-room lumped model + proportional HVAC controller

Modbus/TCP slave (optional, needs `pip install pymodbus`):
  Input registers (FC4, values x10)        Holding regs (FC3/6/16, x10)   Coils (FC1/5)
   0 minute of day (0-1439, not scaled)     0 Admin setpoint               0 Admin HVAC enable
   1 outside temp                           1 Reception setpoint           1 Reception HVAC enable
   2 admin temp   3 reception temp          2 Server setpoint              2 Server HVAC enable
   4 server temp
   5-7  load kW (admin, reception, server)
   8-10 cooling kW (admin, reception, server)
   11   total facility power kW

Usage:
  python3 dc_sim.py                          # console only
  python3 dc_sim.py --modbus --port 5020     # + Modbus slave
  python3 dc_sim.py --start 8                # start at 08:00
"""
import argparse
import asyncio
import random
from dataclasses import dataclass

COP = 3.0  # HVAC efficiency: electrical kW = cooling kW / COP


def outside_temp(h: float) -> float:
    if h < 6:
        return 20.0
    if h < 12:
        return 20.0 + 15.0 * (h - 6) / 6
    if h < 18:
        return 35.0
    return 35.0 - 15.0 * (h - 18) / 6


def office_hours(h: float) -> bool:
    return 9 <= h < 18


@dataclass
class Room:
    name: str
    setpoint: float   # C
    cap: float        # thermal capacity, kJ/K
    ua: float         # envelope conductance, kW/K
    max_cool: float   # kW
    load_full: float  # kW during office hours
    load_min: float   # kW outside office hours
    temp: float = 0.0
    load: float = 0.0
    cool: float = 0.0
    hvac_on: bool = True
    _n: float = 0.0   # slow load noise

    def __post_init__(self):
        self.temp = self.setpoint
        self.kp = self.max_cool / 3.0  # full cooling at +3K above setpoint

    def step(self, dt: float, t_out: float, office: bool):
        base = self.load_full if office else self.load_min
        self._n = 0.95 * self._n + random.gauss(0, 0.01)
        self.load = base * (1 + self._n)
        err = self.temp - self.setpoint
        self.cool = min(max(self.kp * err, 0.0), self.max_cool) if self.hvac_on else 0.0
        leak = self.ua * (t_out - self.temp)
        self.temp += (self.load + leak - self.cool) / self.cap * dt


class DataCentre:
    def __init__(self, start_hour: float = 0.0):
        self.t = start_hour * 3600.0  # simulated seconds
        self.rooms = {
            "admin":     Room("Admin",     24.0, 600,  0.30, 12, 8, 1.0),
            "reception": Room("Reception", 24.0, 400,  0.50, 8, 4, 0.5),
            "server":    Room("Server",    22.0, 2000, 0.40, 60, 40, 16.0),
        }
        self.t_out = outside_temp(self.hour)

    @property
    def hour(self) -> float:
        return (self.t / 3600.0) % 24

    @property
    def day(self) -> int:
        return int(self.t // 86400) + 1

    def step(self, dt: float = 10.0):
        self.t += dt
        self.t_out = outside_temp(self.hour) + random.gauss(0, 0.05)
        office = office_hours(self.hour)
        for r in self.rooms.values():
            r.step(dt, self.t_out, office)

    @property
    def total_kw(self) -> float:
        return sum(r.load + r.cool / COP for r in self.rooms.values())

    def line(self) -> str:
        h = self.hour
        r = self.rooms
        return (f"D{self.day} {int(h):02d}:{int(h % 1 * 60):02d} | "
                f"Out {self.t_out:5.1f}C | "
                f"Admin {r['admin'].temp:5.1f}C {r['admin'].load:5.1f}kW | "
                f"Recep {r['reception'].temp:5.1f}C {r['reception'].load:5.1f}kW | "
                f"Server {r['server'].temp:5.1f}C {r['server'].load:5.1f}kW | "
                f"Total {self.total_kw:5.1f}kW")


# ------------------------------------------------------------------ Modbus
ROOMS = ("admin", "reception", "server")


def build_modbus(dc):
    """pymodbus >= 3.11 SimDevice. Registers are refreshed from / applied to the
    simulation inside an `action` callback on every client access."""
    from pymodbus.simulator import DataType, SimData, SimDevice
    from pymodbus.simulator.simutils import SimUtils

    s10 = lambda v: max(0, int(round(v * 10)))

    def ir_values():
        R = dc.rooms
        return [int(dc.hour * 60), s10(dc.t_out),
                s10(R["admin"].temp), s10(R["reception"].temp), s10(R["server"].temp),
                s10(R["admin"].load), s10(R["reception"].load), s10(R["server"].load),
                s10(R["admin"].cool), s10(R["reception"].cool), s10(R["server"].cool),
                s10(dc.total_kw)]

    async def action(fc, start, address, count, regs, set_values):
        if set_values is not None:                      # client WRITE
            for k, v in enumerate(set_values):
                idx = address + k
                if fc in (6, 16) and idx < 3:
                    dc.rooms[ROOMS[idx]].setpoint = v / 10.0
                elif fc in (5, 15) and idx < 3:
                    dc.rooms[ROOMS[idx]].hvac_on = bool(v)
            return None
        if fc == 4:                                     # input registers
            regs[0:12] = ir_values()
        elif fc == 3:                                   # holding registers
            regs[0:3] = [s10(dc.rooms[k].setpoint) for k in ROOMS]
        elif fc == 1:                                   # coils
            bits = [dc.rooms[k].hvac_on for k in ROOMS] + [False] * 13
            regs[0:1] = SimUtils.bitsToRegisters(bits)
        return None

    return SimDevice(
        id=0,                                           # 0 = answer for any unit id
        simdata=(
            [SimData(0, values=[True] * 3 + [False] * 13, datatype=DataType.BITS)],   # coils
            [SimData(0, values=[False] * 16, datatype=DataType.BITS)],                # discrete inputs
            [SimData(0, values=[240, 240, 220] + [0] * 13, datatype=DataType.REGISTERS)],  # holding
            [SimData(0, values=[0] * 16, datatype=DataType.REGISTERS)],               # input regs
        ),
        action=action,
    )


# -------------------------------------------------------------------- main
async def run(args):
    dc = DataCentre(args.start)
    if args.modbus:
        from pymodbus.server import StartAsyncTcpServer
        asyncio.create_task(StartAsyncTcpServer(context=build_modbus(dc),
                                                address=(args.host, args.port)))
        print(f"Modbus/TCP slave on {args.host}:{args.port}")

    tick = 0.25                       # real seconds per loop
    dt = tick * args.speed * 60       # simulated seconds per loop (default 15 s)
    sub = 5                           # integration substeps
    last_print = -1
    while True:
        for _ in range(sub):
            dc.step(dt / sub)
        minute = int(dc.t // 60)
        if not args.quiet and minute != last_print and minute % args.log_every == 0:
            print(dc.line())
        last_print = minute
        await asyncio.sleep(tick)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--modbus", action="store_true", help="enable Modbus/TCP slave")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5020)
    p.add_argument("--start", type=float, default=0.0, help="start hour (0-24)")
    p.add_argument("--speed", type=float, default=1.0, help="sim minutes per real second")
    p.add_argument("--log-every", type=int, default=10, help="console line every N sim minutes")
    p.add_argument("--quiet", action="store_true")
    try:
        asyncio.run(run(p.parse_args()))
    except KeyboardInterrupt:
        pass
