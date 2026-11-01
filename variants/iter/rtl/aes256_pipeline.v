`timescale 1ns / 1ps
`default_nettype none

// Iterative AES-256 encryption core (baseline for comparison with the
// fully pipelined core). Same ports, same key schedule, same round RTL
// as the original; only the datapath reuse differs.
//
// Interface rules:
//   1. Pulse key_load for one clock with key_in valid.
//   2. Wait until key_ready is high.
//   3. Whenever input_ready is high, input_valid may be asserted with data_in.
//   4. input_ready is high only while the core is idle (not mid-iteration)
//      and a key is ready, so at most one block is in flight at a time.
//   5. output_valid is high for exactly one clock with the ciphertext.
//
// Operation: on acceptance, state <= data_in ^ RK0 and the round counter
// starts at 1. Each following clock feeds the state through ONE shared
// aes_round instance (two instances exist only because FINAL_ROUND is a
// compile-time parameter: a normal round and a final round, muxed by
// round_counter == 14). When the round-14 result is latched, it is also
// presented on data_out with output_valid for one clock and the core
// returns to idle.
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

    // Idle-only acceptance: do not accept while loading a replacement key
    // or while a block is being iterated.
    reg         busy;
    assign input_ready = key_ready && !key_load && !busy;

    // The single reusable round state and its counter (1..14 while busy).
    reg  [127:0] state_reg;
    reg  [4:0]   round_counter;
    reg  [127:0] data_out_reg;
    reg          output_valid_reg;

    assign data_out    = data_out_reg;
    assign output_valid = output_valid_reg;

    // Initial AddRoundKey (same slicing as the original top).
    wire [127:0] initial_round_key = round_keys_flat[1919:1792];

    // Round key for the current iteration (same slicing formula as the
    // original top: round_keys_flat[1919-(128*counter) -: 128]).
    wire [127:0] round_key = round_keys_flat[1919-(128*round_counter) -: 128];

    // Two parameter variants of the same round, muxed at run time because
    // a module parameter cannot be driven by a runtime signal.
    wire [127:0] normal_round_out;
    wire [127:0] final_round_out;
    wire [127:0] round_result = (round_counter == 5'd14)
                              ? final_round_out
                              : normal_round_out;

    aes_round #(
        .FINAL_ROUND (0)
    ) u_round (
        .state_in  (state_reg),
        .round_key (round_key),
        .state_out (normal_round_out)
    );

    aes_round #(
        .FINAL_ROUND (1)
    ) u_final_round (
        .state_in  (state_reg),
        .round_key (round_key),
        .state_out (final_round_out)
    );

    wire accept = input_valid && input_ready;

    always @(posedge clk) begin
        if (reset) begin
            busy             <= 1'b0;
            round_counter    <= 5'd0;
            state_reg        <= 128'b0;
            data_out_reg     <= 128'b0;
            output_valid_reg <= 1'b0;
        end
        else if (key_load) begin
            // Loading a key flushes any block currently being iterated.
            busy             <= 1'b0;
            round_counter    <= 5'd0;
            output_valid_reg <= 1'b0;
        end
        else if (!busy) begin
            // output_valid lasts exactly one clock: it was set on the
            // final-round edge and is cleared on the next edge.
            output_valid_reg <= 1'b0;
            if (accept) begin
                state_reg     <= data_in ^ initial_round_key;
                round_counter <= 5'd1;
                busy          <= 1'b1;
            end
        end
        else begin
            // One round per clock through the shared round instance.
            state_reg        <= round_result;
            output_valid_reg <= 1'b0;
            if (round_counter == 5'd14) begin
                data_out_reg     <= round_result;
                output_valid_reg <= 1'b1;
                busy             <= 1'b0;
                round_counter    <= 5'd0;
            end
            else begin
                round_counter <= round_counter + 1'b1;
            end
        end
    end

endmodule

`default_nettype wire
