PROGRAM dc_ctrl
  VAR
    minute_of_day AT %IW100 : INT;
    t_out AT %IW101 : INT;
    t_admin AT %IW102 : INT;
    t_recep AT %IW103 : INT;
    t_server AT %IW104 : INT;
    load_admin AT %IW105 : INT;
    load_recep AT %IW106 : INT;
    load_server AT %IW107 : INT;
    cool_admin AT %IW108 : INT;
    cool_recep AT %IW109 : INT;
    cool_server AT %IW110 : INT;
    p_total AT %IW111 : INT;
    sp_admin AT %QW100 : INT;
    sp_recep AT %QW101 : INT;
    sp_server AT %QW102 : INT;
    hvac_admin AT %QX100.0 : BOOL;
    hvac_recep AT %QX100.1 : BOOL;
    hvac_server AT %QX100.2 : BOOL;
    hmi_minute AT %QW0 : INT;
    hmi_t_out AT %QW1 : INT;
    hmi_admin AT %QW2 : INT;
    hmi_recep AT %QW3 : INT;
    hmi_server AT %QW4 : INT;
    hmi_power AT %QW5 : INT;
    hmi_load_admin AT %QW6 : INT;
    hmi_load_recep AT %QW7 : INT;
    hmi_load_server AT %QW8 : INT;
    hmi_cool_admin AT %QW9 : INT;
    hmi_cool_recep AT %QW10 : INT;
    hmi_cool_server AT %QW11 : INT;
    hmi_hvac_kw AT %QW12 : INT;
    hmi_sp_server AT %QW13 : INT;
    cmd_sp_server AT %QW20 : INT;
    alarm_warn AT %QX0.0 : BOOL;
    alarm_crit AT %QX0.1 : BOOL;
    office_hrs AT %QX0.2 : BOOL;
    hvac_running AT %QX0.3 : BOOL;
    cmd_manual AT %QX0.4 : BOOL;
    cmd_hvac_on AT %QX0.5 : BOOL;
    interlock AT %QX0.6 : BOOL;
  END_VAR
  VAR
    target_sp : INT;
  END_VAR

  (* ---------------------------------------------------------------------
     Register map (PLC Modbus server, all temperatures degC x10, power kW x10)
     HR0 minute  HR1 outside  HR2 admin  HR3 reception  HR4 server  HR5 total kW
     HR6-8 loads (admin, reception, server IT)   HR9-11 cooling kW (thermal)
     HR12 server HVAC electrical kW   HR13 server setpoint in use
     HR20 server setpoint COMMAND (SCADA writes, PLC clamps 18.0-30.0 C)
     Coil0 warning >28C  Coil1 critical >32C  Coil2 office hours
     Coil3 server HVAC running  Coil4 MANUAL MODE cmd  Coil5 HVAC ENABLE cmd (manual)
     Coil6 safety interlock active (critical temp forces HVAC on, setpoint 22C)
     --------------------------------------------------------------------- *)

  office_hrs := (minute_of_day >= 540) AND (minute_of_day < 1080);

  IF office_hrs THEN
    sp_admin := 240;
    sp_recep := 240;
  ELSE
    sp_admin := 280;
    sp_recep := 280;
  END_IF;
  hvac_admin := TRUE;
  hvac_recep := TRUE;

  IF cmd_manual THEN
    target_sp := cmd_sp_server;
    IF target_sp < 180 THEN
      target_sp := 180;
    END_IF;
    IF target_sp > 300 THEN
      target_sp := 300;
    END_IF;
    hvac_server := cmd_hvac_on;
  ELSE
    target_sp := 220;
    hvac_server := TRUE;
  END_IF;

  IF t_server > 320 THEN
    interlock := TRUE;
  ELSIF t_server < 280 THEN
    interlock := FALSE;
  END_IF;
  IF interlock THEN
    hvac_server := TRUE;
    target_sp := 220;
  END_IF;
  sp_server := target_sp;

  alarm_warn := t_server > 280;
  alarm_crit := t_server > 320;
  hvac_running := hvac_server AND (cool_server > 5);

  hmi_minute := minute_of_day;
  hmi_t_out := t_out;
  hmi_admin := t_admin;
  hmi_recep := t_recep;
  hmi_server := t_server;
  hmi_power := p_total;
  hmi_load_admin := load_admin;
  hmi_load_recep := load_recep;
  hmi_load_server := load_server;
  hmi_cool_admin := cool_admin;
  hmi_cool_recep := cool_recep;
  hmi_cool_server := cool_server;
  hmi_hvac_kw := cool_server / 3;
  hmi_sp_server := target_sp;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM inst0 WITH task0 : dc_ctrl;
  END_RESOURCE
END_CONFIGURATION
