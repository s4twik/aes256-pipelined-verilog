`timescale 1ns / 1ps
`default_nettype none

// Mix one four-byte AES state column in GF(2^8).
module aes_mix_single_column (
    input  wire [31:0] column_in,
    output wire [31:0] column_out
);

    wire [7:0] a0 = column_in[31:24];
    wire [7:0] a1 = column_in[23:16];
    wire [7:0] a2 = column_in[15:8];
    wire [7:0] a3 = column_in[7:0];

    // Multiplication by x (02 hex) modulo x^8+x^4+x^3+x+1.
    function [7:0] xtime;
        input [7:0] value;
        begin
            xtime = {value[6:0], 1'b0} ^ (8'h1b & {8{value[7]}});
        end
    endfunction

    wire [7:0] mul2_a0 = xtime(a0);
    wire [7:0] mul2_a1 = xtime(a1);
    wire [7:0] mul2_a2 = xtime(a2);
    wire [7:0] mul2_a3 = xtime(a3);

    // Multiplication by 03 is xtime(a) XOR a.
    assign column_out[31:24] = mul2_a0 ^ (mul2_a1 ^ a1) ^ a2 ^ a3;
    assign column_out[23:16] = a0 ^ mul2_a1 ^ (mul2_a2 ^ a2) ^ a3;
    assign column_out[15:8]  = a0 ^ a1 ^ mul2_a2 ^ (mul2_a3 ^ a3);
    assign column_out[7:0]   = (mul2_a0 ^ a0) ^ a1 ^ a2 ^ mul2_a3;

endmodule

// Apply MixColumns to the four independent 32-bit columns of the AES state.
module aes_mix_columns (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    aes_mix_single_column u_column0 (
        .column_in  (state_in[127:96]),
        .column_out (state_out[127:96])
    );

    aes_mix_single_column u_column1 (
        .column_in  (state_in[95:64]),
        .column_out (state_out[95:64])
    );

    aes_mix_single_column u_column2 (
        .column_in  (state_in[63:32]),
        .column_out (state_out[63:32])
    );

    aes_mix_single_column u_column3 (
        .column_in  (state_in[31:0]),
        .column_out (state_out[31:0])
    );

endmodule

`default_nettype wire
