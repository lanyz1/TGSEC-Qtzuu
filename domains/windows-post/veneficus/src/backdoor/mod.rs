/*
** *********************************************************************
** *********************************************************************
**
**                              DISCLAIMER
**       For educational purposes only. 2026 All rights reversed.
**
** *********************************************************************
** *********************************************************************
*/

// backdoor/mod.rs — backdoor module entry.
//
// Exists so `mod backdoor;` in main.rs resolves. Only HVNC is exported.
// HVNC is a localhost RFB skeleton, not a hidden-desktop VNC.

pub mod hvnc;
