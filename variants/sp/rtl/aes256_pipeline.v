`timescale 1ns / 1ps
`default_nettype none

// Sub-pipelined AES-256 encryption core.
//
// Same interface and key-schedule behaviour as the original
// aes256_pipeline, but every AES round is split into two pipeline
// stages: SubBytes+ShiftRows are registered into a mid-round register,
// then MixColumns+AddRoundKey are registered into the round-output
// register. This inserts one extra register bank per round, shortening
// the combinational path per stage at the cost of doubled latency.
//
// Interface rules:
//   1. Pulse key_load for one clock with key_in valid.
//   2. Wait until key_ready is high.
//   3. Whenever input_ready is high, input_valid may be asserted with data_in.
//   4. After the pipeline fills, one ciphertext can emerge every clock.
//
// There is intentionally no output backpressure in this core. The
// receiver must capture data_out whenever output_valid is high.
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

    // Register banks: 1 (stage 0) + 14 mid-round + 14 round-output = 29.
    // Stage 0 stores the state after the initial AddRoundKey operation.
    // mid_pipeline[n] stores the first-half (SubBytes+ShiftRows) result
    // of round n; state_pipeline[n] stores the second-half
    // (MixColumns+AddRoundKey) result of round n.
    reg  [127:0] state_pipeline [0:14];
    reg  [127:0] mid_pipeline   [1:14];
    wire [127:0] first_half_result  [1:14];
    wire [127:0] second_half_result [1:14];
    reg  [28:0]  valid_pipeline;

    wire [127:0] initial_round_key = round_keys_flat[1919:1792];
    wire [127:0] initial_state;

    aes_add_round_key u_initial_add_round_key (
        .state_in  (data_in),
        .round_key (initial_round_key),
        .state_out (initial_state)
    );

    genvar round_number;
    generate
        // First halves of rounds 1 through 14: SubBytes + ShiftRows,
        // combinationally fed from the previous round-output register.
        for (round_number = 1; round_number <= 14; round_number = round_number + 1) begin : gen_first_halves
            aes_round_first_half u_first_half (
                .state_in  (state_pipeline[round_number-1]),
                .state_out (first_half_result[round_number])
            );
        end

        // Second halves of rounds 1 through 13 include MixColumns.
        // They are fed from the mid-round register, never from the
        // combinational first-half result -- that register is the
        // entire point of sub-pipelining.
        for (round_number = 1; round_number <= 13; round_number = round_number + 1) begin : gen_second_halves
            aes_round_second_half #(
                .FINAL_ROUND (0)
            ) u_second_half (
                .state_in  (mid_pipeline[round_number]),
                .round_key (round_keys_flat[1919-(128*round_number) -: 128]),
                .state_out (second_half_result[round_number])
            );
        end
    endgenerate

    // Second half of round 14 omits MixColumns.
    aes_round_second_half #(
        .FINAL_ROUND (1)
    ) u_final_second_half (
        .state_in  (mid_pipeline[14]),
        .round_key (round_keys_flat[127:0]),
        .state_out (second_half_result[14])
    );

    integer stage_index;
    always @(posedge clk) begin
        // Datapath registers intentionally have no reset. Only their matching
        // valid bits determine whether their contents represent useful data.
        state_pipeline[0] <= initial_state;
        for (stage_index = 1; stage_index < 15; stage_index = stage_index + 1) begin
            mid_pipeline[stage_index]   <= first_half_result[stage_index];
            state_pipeline[stage_index] <= second_half_result[stage_index];
        end
    end

    always @(posedge clk) begin
        if (reset || key_load) begin
            // Loading a key flushes any blocks currently in the pipeline.
            valid_pipeline <= 29'b0;
        end
        else begin
            valid_pipeline <= {
                valid_pipeline[27:0],
                input_valid && input_ready
            };
        end
    end

    assign data_out     = state_pipeline[14];
    assign output_valid = valid_pipeline[28];

endmodule

`default_nettype wire
