`timescale 1ns / 1ps
`default_nettype none

// AddRoundKey is a bitwise XOR of the 128-bit state and round key.
module aes_add_round_key (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);

    assign state_out = state_in ^ round_key;

endmodule

`default_nettype wire
