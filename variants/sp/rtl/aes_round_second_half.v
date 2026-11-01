`timescale 1ns / 1ps
`default_nettype none

// Second half of one combinational AES encryption round:
// MixColumns (unless FINAL_ROUND=1) followed by AddRoundKey. This is
// the portion of the original aes_round that sits after the mid-round
// pipeline register in the sub-pipelined variant. Its input must be
// fed from that register, never directly from aes_round_first_half.
// Set FINAL_ROUND=1 for round 14, where MixColumns must be omitted.
module aes_round_second_half #(
    parameter FINAL_ROUND = 0
) (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);

    wire [127:0] after_mix_columns;
    wire [127:0] before_add_round_key;

    generate
        if (FINAL_ROUND == 0) begin : gen_normal_round
            aes_mix_columns u_mix_columns (
                .state_in  (state_in),
                .state_out (after_mix_columns)
            );
            assign before_add_round_key = after_mix_columns;
        end
        else begin : gen_final_round
            // The AES final round deliberately bypasses MixColumns.
            assign after_mix_columns    = 128'b0;
            assign before_add_round_key = state_in;
        end
    endgenerate

    aes_add_round_key u_add_round_key (
        .state_in  (before_add_round_key),
        .round_key (round_key),
        .state_out (state_out)
    );

endmodule

`default_nettype wire
