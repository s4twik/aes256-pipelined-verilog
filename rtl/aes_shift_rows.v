`timescale 1ns / 1ps
`default_nettype none

// AES ShiftRows transformation.
//
// Byte ordering is column-major, as used by NIST AES:
//   state_in = {s0, s1, s2, s3, s4, ..., s15}
//
// Matrix before ShiftRows:       Matrix after ShiftRows:
//   s0   s4   s8  s12              s0   s4   s8  s12
//   s1   s5   s9  s13              s5   s9  s13   s1
//   s2   s6  s10  s14             s10  s14   s2   s6
//   s3   s7  s11  s15             s15   s3   s7  s11
//
// This module is purely combinational. Pipeline registers should be added
// at the round/stage boundary outside this module.
module aes_shift_rows (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    // Flatten the shifted matrix back into column-major byte order.
    assign state_out = {
        state_in[127:120],  // s0
        state_in[ 87: 80],  // s5
        state_in[ 47: 40],  // s10
        state_in[  7:  0],  // s15

        state_in[ 95: 88],  // s4
        state_in[ 55: 48],  // s9
        state_in[ 15:  8],  // s14
        state_in[103: 96],  // s3

        state_in[ 63: 56],  // s8
        state_in[ 23: 16],  // s13
        state_in[111:104],  // s2
        state_in[ 71: 64],  // s7

        state_in[ 31: 24],  // s12
        state_in[119:112],  // s1
        state_in[ 79: 72],  // s6
        state_in[ 39: 32]   // s11
    };

endmodule

`default_nettype wire
