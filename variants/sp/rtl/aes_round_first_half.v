`timescale 1ns / 1ps
`default_nettype none

// First half of one combinational AES encryption round:
// SubBytes followed by ShiftRows. This is the portion of the original
// aes_round that sits before the mid-round pipeline register in the
// sub-pipelined variant.
module aes_round_first_half (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    wire [127:0] after_sub_bytes;

    aes_sub_bytes u_sub_bytes (
        .state_in  (state_in),
        .state_out (after_sub_bytes)
    );

    aes_shift_rows u_shift_rows (
        .state_in  (after_sub_bytes),
        .state_out (state_out)
    );

endmodule

`default_nettype wire
