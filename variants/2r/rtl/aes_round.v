`timescale 1ns / 1ps
`default_nettype none

// One combinational AES encryption round.
// Set FINAL_ROUND=1 for round 14, where MixColumns must be omitted.
module aes_round #(
    parameter FINAL_ROUND = 0
) (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);

    wire [127:0] after_sub_bytes;
    wire [127:0] after_shift_rows;
    wire [127:0] after_mix_columns;
    wire [127:0] before_add_round_key;

    aes_sub_bytes u_sub_bytes (
        .state_in  (state_in),
        .state_out (after_sub_bytes)
    );

    aes_shift_rows u_shift_rows (
        .state_in  (after_sub_bytes),
        .state_out (after_shift_rows)
    );

    generate
        if (FINAL_ROUND == 0) begin : gen_normal_round
            aes_mix_columns u_mix_columns (
                .state_in  (after_shift_rows),
                .state_out (after_mix_columns)
            );
            assign before_add_round_key = after_mix_columns;
        end
        else begin : gen_final_round
            // The AES final round deliberately bypasses MixColumns.
            assign after_mix_columns    = 128'b0;
            assign before_add_round_key = after_shift_rows;
        end
    endgenerate

    aes_add_round_key u_add_round_key (
        .state_in  (before_add_round_key),
        .round_key (round_key),
        .state_out (state_out)
    );

endmodule

`default_nettype wire
