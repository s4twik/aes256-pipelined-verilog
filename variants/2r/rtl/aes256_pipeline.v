`timescale 1ns / 1ps
`default_nettype none

// Fully pipelined AES-256 encryption core -- two rounds per pipeline stage.
//
// Interface rules (identical to the original one-round-per-stage core):
//   1. Pulse key_load for one clock with key_in valid.
//   2. Wait until key_ready is high.
//   3. Whenever input_ready is high, input_valid may be asserted with data_in.
//   4. After the pipeline fills, one ciphertext can emerge every clock.
//
// This variant folds two AES rounds into each pipeline stage, so the 14
// rounds are spread over 7 double-round stages instead of 14 single-round
// stages. Throughput is unchanged (one block per clock); latency from input
// acceptance to output_valid is 7 cycles.
//
// There is intentionally no output backpressure in this first high-throughput
// core. The receiver must capture data_out whenever output_valid is high.
module aes256_pipeline (
    input  wire         clk,
    input  wire         reset,

    input  wire         key_load,
    input  wire [255:0] key_in,
    output wire         key_busy,
    output wire         key_ready,

    input  wire [127:0] data_in,
    input  wire         input_valid,
    output wire         input_ready,

    output wire [127:0] data_out,
    output wire         output_valid
);

    wire [1919:0] round_keys_flat;

    aes256_key_schedule u_key_schedule (
        .clk             (clk),
        .reset           (reset),
        .key_load        (key_load),
        .key_in          (key_in),
        .key_busy        (key_busy),
        .key_ready       (key_ready),
        .round_keys_flat (round_keys_flat)
    );

    // Do not accept a block while loading a replacement key.
    assign input_ready = key_ready && !key_load;

    // Stage 0 stores the state after the initial AddRoundKey operation.
    // Stages 1..7 each store the result of two cascaded rounds:
    // stage s computes rounds (2s-1) and 2s from state_pipe[s-1].
    // Stage 7 therefore computes rounds 13 and 14 (the final round).
    reg  [127:0] state_pipe   [0:7];
    wire [127:0] pair_mid     [1:7];
    wire [127:0] stage_result [1:7];
    reg  [7:0]   valid_pipeline;

    wire [127:0] initial_round_key = round_keys_flat[1919:1792];
    wire [127:0] initial_state;

    aes_add_round_key u_initial_add_round_key (
        .state_in  (data_in),
        .round_key (initial_round_key),
        .state_out (initial_state)
    );

    genvar stage_number;
    generate
        // Stages 1..6: round pairs (1,2), (3,4), ..., (11,12).
        // Neither round of these pairs is the final round, so both
        // instances include MixColumns (FINAL_ROUND=0).
        for (stage_number = 1; stage_number <= 6; stage_number = stage_number + 1) begin : gen_double_round_stages
            aes_round #(
                .FINAL_ROUND (0)
            ) u_round_first (
                .state_in  (state_pipe[stage_number-1]),
                .round_key (round_keys_flat[1919-(128*(2*stage_number-1)) -: 128]),
                .state_out (pair_mid[stage_number])
            );

            aes_round #(
                .FINAL_ROUND (0)
            ) u_round_second (
                .state_in  (pair_mid[stage_number]),
                .round_key (round_keys_flat[1919-(128*(2*stage_number)) -: 128]),
                .state_out (stage_result[stage_number])
            );
        end
    endgenerate

    // Stage 7: rounds 13 and 14. Round 13 includes MixColumns;
    // round 14 is the final round and omits MixColumns (FINAL_ROUND=1).
    aes_round #(
        .FINAL_ROUND (0)
    ) u_round_13 (
        .state_in  (state_pipe[6]),
        .round_key (round_keys_flat[1919-(128*13) -: 128]),
        .state_out (pair_mid[7])
    );

    aes_round #(
        .FINAL_ROUND (1)
    ) u_round_14 (
        .state_in  (pair_mid[7]),
        .round_key (round_keys_flat[127:0]),
        .state_out (stage_result[7])
    );

    integer stage_index;
    always @(posedge clk) begin
        // Datapath registers intentionally have no reset. Only their matching
        // valid bits determine whether their contents represent useful data.
        state_pipe[0] <= initial_state;
        for (stage_index = 1; stage_index < 8; stage_index = stage_index + 1) begin
            state_pipe[stage_index] <= stage_result[stage_index];
        end
    end

    always @(posedge clk) begin
        if (reset || key_load) begin
            // Loading a key flushes any blocks currently in the pipeline.
            valid_pipeline <= 8'b0;
        end
        else begin
            valid_pipeline <= {
                valid_pipeline[6:0],
                input_valid && input_ready
            };
        end
    end

    assign data_out     = state_pipe[7];
    assign output_valid = valid_pipeline[7];

endmodule

`default_nettype wire
